// Package profile is where the CLI keeps its credential.
package profile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

func path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("no home directory")
	}
	return filepath.Join(home, ".keyway", "config.yml"), nil
}

// Resolve is the profile to use: flags first, then what `login` saved. A nil
// url or token means the flag (or its environment variable) was not given.
func Resolve(url, token *string) (Profile, error) {
	saved, err := load()
	if err != nil {
		return Profile{}, err
	}

	var resolved Profile
	switch {
	case url != nil:
		resolved.URL = *url
	case saved != nil:
		resolved.URL = saved.URL
	default:
		return Profile{}, errors.New("no keyway url; run `keyway login <url>` or pass --url")
	}
	switch {
	case token != nil:
		resolved.Token = *token
	case saved != nil:
		resolved.Token = saved.Token
	default:
		return Profile{}, errors.New("no token; run `keyway login <url>` or pass --token")
	}
	return resolved, nil
}

func load() (*Profile, error) {
	file, err := path()
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	var saved Profile
	if err := yaml.Unmarshal(text, &saved); err != nil {
		return nil, err
	}
	return &saved, nil
}

// Login signs in by sending somebody to the console to mint a token.
//
// The CLI does not mint over the API, deliberately: minting passes through a
// browser session, which is what keeps a token's remembered groups seeded by
// a real sign-in (ADR-0004). It also means a leaked CLI credential cannot
// spawn replacements that survive revoking it.
func Login(in io.Reader, out io.Writer, url string) error {
	url = strings.TrimRight(url, "/")
	tokensPage := url + "/tokens"

	fmt.Fprintf(out, "Open %s and create a token, then paste it here.\n", tokensPage)
	if err := openBrowser(tokensPage); err != nil {
		fmt.Fprintf(out, "(could not open a browser: %v)\n", err)
	}
	fmt.Fprint(out, "Token: ")

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	token := strings.TrimSpace(line)

	if !strings.HasPrefix(token, "kw-") {
		return errors.New("that does not look like a keyway token (they start with `kw-`)")
	}

	if err := save(Profile{URL: url, Token: token}); err != nil {
		return err
	}
	file, err := path()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Saved to %s.\n", file)
	return nil
}

func save(profile Profile) error {
	file, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	text, err := yaml.Marshal(profile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, text, 0o600); err != nil {
		return err
	}
	// A file holding a long-lived credential should not be world-readable —
	// and WriteFile's mode only applies when it creates the file, so an
	// overwrite is restricted explicitly.
	return os.Chmod(file, 0o600)
}

// openBrowser is a variable so a test can sign in without a window opening.
var openBrowser = func(url string) error {
	opener := "xdg-open"
	switch runtime.GOOS {
	case "darwin":
		opener = "open"
	case "windows":
		opener = "explorer"
	}
	// Started and not waited for, like the Rust CLI's spawn: the CLI exits
	// long before the browser does.
	return exec.Command(opener, url).Start()
}
