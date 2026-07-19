package uploader

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-olive/olive/engine/util"
	"github.com/go-olive/olive/foundation/biliup"
	"github.com/sirupsen/logrus"
)

const (
	olivetrash   = "olivetrash"
	olivearchive = "olivearchive"
	olivebiliup  = "olivebiliup"
	oliveshell   = "oliveshell"
)

// DefaultHandlerFunc is returned by TaskMux.MustGetHandler when no handler
// matches. It used to defer to OliveDefault, which would run command
// Args[0] verbatim via exec.Command -- turning a stray/unknown post cmd path
// into an unauthenticated RCE. The new behavior is to refuse loudly so that
// a misconfigured or fraudulent task type never executes anything.
var DefaultHandlerFunc = TaskHandlerFunc(RejectUnknownTask)

func init() {
	DefaultTaskMux.RegisterHandler(olivetrash, TaskHandlerFunc(OliveTrash))
	DefaultTaskMux.RegisterHandler(olivearchive, TaskHandlerFunc(OliveArchive))
	DefaultTaskMux.RegisterHandler(olivebiliup, TaskHandlerFunc(OliveBiliup))
	// oliveshell is the only task type that runs a caller-supplied binary.
	// It is gated behind API authentication (severity: privileged) and is
	// validated at ingestion time to require a non-empty Args slice.
	DefaultTaskMux.RegisterHandler(oliveshell, TaskHandlerFunc(OliveShell))
}

// RejectUnknownTask refuses to run any task whose Path is not on the engine's
// whitelist. This is defense-in-depth: validate.CheckPostCmds already rejects
// unknown paths at the API layer, but the uploader stays the last gate.
func RejectUnknownTask(t *Task) error {
	path := ""
	if t.Cmd != nil {
		path = t.Cmd.Path
	}
	return fmt.Errorf("uploader: refusing to execute unknown post cmd %q (allowed: olivetrash, olivearchive, olivebiliup, oliveshell)", path)
}

// OliveShell is the renamed OliveDefault: it is invoked only for the
// explicitly-registered oliveshell task type, so an attacker can no longer
// reach it by stuffing arbitrary path strings into PostCmds. The handler
// expects Cmd.Args[0] to be the binary to invoke and passes the inbound
// FILE_PATH through the child environment.
func OliveShell(t *Task) error {
	doneChan := make(chan struct{})
	defer close(doneChan)

	if t.Cmd == nil || len(t.Cmd.Args) == 0 {
		return errors.New("oliveshell: empty command")
	}

	cmd := exec.Command(t.Cmd.Args[0], t.Cmd.Args[1:]...)

	envFilepath := "FILE_PATH=" + t.Filepath
	cmd.Env = append([]string{envFilepath}, t.Cmd.Env...)
	cmd.Dir = t.Cmd.Dir

	go func() {
		select {
		case <-t.StopChan:
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			return
		case <-doneChan:
			return
		}
	}()

	resp, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	t.log.Infof("oliveshell success: %s", resp)
	return nil
}

// OliveDefault is kept ONLY as a backward-compatible alias for unit tests or
// third-party callers that imported the old symbol. New code must call
// OliveShell explicitly; OliveDefault now delegates to the refusing handler
// so the export does not become a silent attacker entrypoint.
var OliveDefault = RejectUnknownTask

func OliveTrash(t *Task) error {
	return os.Remove(t.Filepath)
}

func OliveArchive(t *Task) error {
	dir := filepath.Dir(t.Filepath)
	dest := filepath.Join(dir, "archive")
	if err := os.MkdirAll(dest, os.ModePerm); err != nil {
		return err
	}
	return t.move(dest)
}

func (t *Task) move(dest string) error {
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(dest, os.ModePerm)
		return err
	}

	base := filepath.Base(t.Filepath)
	dest = filepath.Join(dest, base)
	return util.MoveFile(t.Filepath, dest)
}

func OliveBiliup(t *Task) error {
	t.log.WithFields(logrus.Fields{
		"filepath": t.Filepath,
	}).Info("upload start")

	biliupConfig := biliup.Config{
		CookieFilepath:    t.cfg.CookieFilepath,
		VideoFilepath:     t.Filepath,
		Threads:           t.cfg.Threads,
		MaxBytesPerSecond: t.cfg.MaxBytesPerSecond,
	}
	err := biliup.New(biliupConfig).Upload()
	if err == nil {
		t.log.WithFields(logrus.Fields{
			"filepath": t.Filepath,
		}).Info("upload succeed")
		return nil
	}

	return err
}
