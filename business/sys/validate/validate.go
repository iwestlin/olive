// Package validate contains the support for validating models.
package validate

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-olive/olive/engine/config"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
)

// validate holds the settings and caches for validating request struct values.
var validate *validator.Validate

// translator is a cache of locale and translation information.
var translator ut.Translator

// PostCmdWhitelist enumerates the only `path` values the engine is willing
// to interpret from user-supplied PostCmds. Anything else is rejected at
// validation time and again at execution time, removing the previous
// "any path becomes a binary to execute" RCE.
var PostCmdWhitelist = map[string]bool{
	"olivetrash":   true,
	"olivearchive": true,
	"olivebiliup":  true,
	"oliveshell":   true,
}

// PostCmdSchema is the wire shape of an entry inside a show's PostCmds JSON
// array. We deliberately do NOT unmarshal into exec.Cmd directly because
// exec.Cmd's exported fields (Path, Args, Env, Dir, Stdin, Stdout, ...) make
// it look like every field is fair game, and the engine previously fed
// arbitrary Path values into exec.Command. The explicit schema pins down the
// only fields the task runner actually consumes.
type PostCmdSchema struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// emailRegex is the regular expression used to determine if a string is an email.
// https://github.com/go-playground/validator/blob/v10.10.0/regexes.go#L73
var emailRegex *regexp.Regexp

func init() {

	// Instantiate a validator.
	validate = validator.New()

	// Create a translator for english so the error messages are
	// more human-readable than technical.
	translator, _ = ut.New(en.New(), en.New()).GetTranslator("en")

	// Register the english error messages for use.
	en_translations.RegisterDefaultTranslations(validate, translator)

	// Use JSON tag names for errors instead of Go struct names.
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	// emailRegexString is the regular expression string used to compile into a regexp.
	// https://github.com/go-playground/validator/blob/v10.10.0/regexes.go#L18
	const emailRegexString = "^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	emailRegex = regexp.MustCompile(emailRegexString)
}

// Check validates the provided model against it's declared tags.
func Check(val any) error {
	if err := validate.Struct(val); err != nil {

		// Use a type assertion to get the real error value.
		verrors, ok := err.(validator.ValidationErrors)
		if !ok {
			return err
		}

		var fields FieldErrors
		for _, verror := range verrors {
			field := FieldError{
				Field: verror.Field(),
				Error: verror.Translate(translator),
			}
			fields = append(fields, field)
		}

		return fields
	}

	return nil
}

// GenerateID generate a unique id for entities.
func GenerateID() string {
	return uuid.NewString()
}

// CheckID validates that the format of an id is valid.
func CheckID(id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.New("ID is not in its proper form")
	}
	return nil
}

// CheckEmail validates that the string is an email.
func CheckEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// CheckSafePath rejects path inputs that allow an untrusted caller to
// escape the recording base directory. The rules are:
//   - the empty string is allowed (engine falls back to cfg defaults);
//   - the string must not contain a NUL byte;
//   - the string must not contain a ".." path component (after splitting on
//     both / and \, the cross-platform separators Windows and POSIX use);
//   - the string must not contain a leading "/" or "\" that turns the path
//     into an absolute one outside any reasonable base directory;
//   - the rendered template is allowed to produce sub-paths like
//     "{{ .StreamerName }}/archive/path", but only using single relative
//     segments -- callers should additionally sanitize after rendering.
//
// This is intentionally a heuristic: it covers the obvious traversal
// attacks without trying to render every possible template early.
func CheckSafePath(p string) error {
	if p == "" {
		return nil
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("path contains NUL byte: %q", p)
	}
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return fmt.Errorf("path contains parent-directory traversal: %q", p)
		}
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return fmt.Errorf("path must be relative (refusing absolute path): %q", p)
	}
	return nil
}

// CheckSafeFilename is the stricter check applied to the rendered output
// template. The window for the template is just a top-level filename, so a
// path separator alone is enough to refuse it.
func CheckSafeFilename(p string) error {
	if err := CheckSafePath(p); err != nil {
		return err
	}
	if strings.ContainsRune(p, '/') || strings.ContainsRune(p, '\\') {
		return fmt.Errorf("filename must not contain a path separator: %q", p)
	}
	return nil
}

// CheckPostCmds validates that the PostCmds format is valid AND that every
// entry's Path is on the engine's whitelisted set of task types. This is the
// choke point that prevents an untrusted caller from injecting arbitrary
// binaries into the engine's post-record execution path.
func CheckPostCmds(postCmds string) error {
	if postCmds == "" {
		return nil
	}
	var cmds []PostCmdSchema
	if err := jsoniter.UnmarshalFromString(postCmds, &cmds); err != nil {
		return err
	}
	for i, c := range cmds {
		if !PostCmdWhitelist[c.Path] {
			return fmt.Errorf("post cmds[%d]: unsupported path %q (allowed: olivetrash, olivearchive, olivebiliup, oliveshell)", i, c.Path)
		}
		// oliveshell runs an arbitrary binary, so its args must be present
		// and non-empty. The other three task types ignore Args.
		if c.Path == "oliveshell" && len(c.Args) == 0 {
			return fmt.Errorf("post cmds[%d]: oliveshell requires at least one arg (the binary to run)", i)
		}
	}
	return nil
}

// SafePostCmdUsage records whether the supplied path is on the whitelist.
func SafePostCmdUsage(path string) bool { return PostCmdWhitelist[path] }

// ToExecCmds converts a verified PostCmds JSON document into []*exec.Cmd
// instances that the engine already knows how to dispatch. The Cmd.Path
// field carries the whitelisted task-type identifier (it is NOT a binary
// path); Cmd.Args carries the args for the oliveshell runner (and the
// task type itself as Args[0], matching the historical format).
func ToExecCmds(postCmds string) ([]*exec.Cmd, error) {
	if postCmds == "" {
		return nil, nil
	}
	if err := CheckPostCmds(postCmds); err != nil {
		return nil, err
	}
	var cmds []PostCmdSchema
	if err := jsoniter.UnmarshalFromString(postCmds, &cmds); err != nil {
		return nil, err
	}
	out := make([]*exec.Cmd, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, &exec.Cmd{Path: c.Path, Args: c.Args})
	}
	return out, nil
}

// CheckSplitRule validates that the SplitRule format is valid.
func CheckSplitRule(splitRule string) error {
	if splitRule == "" {
		return nil
	}
	var tmp struct {
		FileSize int64
		Duration string
	}
	return jsoniter.UnmarshalFromString(splitRule, &tmp)
}

// CheckConfig validates that the Config format is valid.
func CheckConfig(key, value string) error {
	switch key {
	case config.CoreConfigKey:
		var c config.Config
		return jsoniter.UnmarshalFromString(value, &c)
	default:
		return fmt.Errorf("unkown config key[%s]", key)
	}
}
