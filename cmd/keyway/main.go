// The keyway command-line client, ported from Rust (ADR-0006).
//
// Seven commands, and the two omissions are the interesting part: there is no
// `delete` and no ownership transfer (ADR-0005). The split is by blast radius
// rather than by read/write — a mistaken grant is visible in the audit log
// and revocable in a click, whereas a deleted secret has no undo, and a
// non-interactive `delete` in a CI script is the one operation with no way
// back.
//
// It speaks the HTTP API and defines its own wire types. Depending on the
// server's packages would compile the whole backend — database driver, cloud
// SDKs and all — into a binary that formats output.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kotsmile/keyway/cmd/keyway/internal/output"
	"github.com/kotsmile/keyway/cmd/keyway/internal/profile"
	"github.com/kotsmile/keyway/cmd/keyway/internal/wire"
)

// version tracks the Cargo workspace version until the Rust crates go.
const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.LookupEnv))
}

// usageError marks a mistake in how the CLI was invoked, which exits 2 — the
// same split clap draws between "you typed it wrong" and "it did not work".
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	root := newRoot(stdin, stdout, stderr, lookupEnv)

	if len(args) == 0 {
		// No command at all: help on stderr and exit 2, as under clap.
		root.SetOut(stderr)
		_ = root.Help()
		return 2
	}
	if _, _, err := root.Find(args); err != nil {
		// An unknown command is a usage error too.
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			return 2
		}
		return 1
	}
	return 0
}

func newRoot(stdin io.Reader, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) *cobra.Command {
	var (
		urlFlag   string
		tokenFlag string
		jsonFlag  bool
		yamlFlag  bool
	)
	printer := output.Printer{Out: stdout, Err: stderr}

	root := &cobra.Command{
		Use:          "keyway",
		Short:        "Talk to a keyway console",
		Version:      version,
		SilenceUsage: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if jsonFlag && yamlFlag {
				return usageError{errors.New("--json cannot be used with --yaml")}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return usageError{errors.New("a command is required; run `keyway --help`")}
		},
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.CompletionOptions.DisableDefaultCmd = true
	// Registered by hand for the capital -V shorthand clap uses.
	root.Flags().BoolP("version", "V", false, "Print version")

	persistent := root.PersistentFlags()
	persistent.StringVar(&urlFlag, "url", "",
		"Where keyway lives. Falls back to the saved profile [env: KEYWAY_URL]")
	persistent.StringVar(&tokenFlag, "token", "",
		"An API token. Falls back to the saved profile [env: KEYWAY_TOKEN]")
	persistent.BoolVar(&jsonFlag, "json", false, "")
	persistent.BoolVar(&yamlFlag, "yaml", false, "")

	format := func() output.Format {
		switch {
		case yamlFlag:
			return output.YAML
		case jsonFlag:
			return output.JSON
		default:
			return output.Plain
		}
	}

	// option is a flag value if given, then its environment variable, then
	// nil — the nil is what lets the saved profile speak last.
	option := func(name, env, value string) *string {
		if persistent.Changed(name) {
			return &value
		}
		if fromEnv, ok := lookupEnv(env); ok {
			return &fromEnv
		}
		return nil
	}
	dial := func() (*wire.Client, error) {
		resolved, err := profile.Resolve(
			option("url", "KEYWAY_URL", urlFlag),
			option("token", "KEYWAY_TOKEN", tokenFlag),
		)
		if err != nil {
			return nil, err
		}
		return wire.NewClient(resolved), nil
	}

	var listStore string
	list := &cobra.Command{
		Use:   "list",
		Short: "Every secret you can see",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := dial()
			if err != nil {
				return err
			}
			secrets, err := client.List(cmd.Context())
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("store") {
				kept := secrets[:0]
				for _, secret := range secrets {
					if secret.Store == listStore {
						kept = append(kept, secret)
					}
				}
				secrets = kept
			}
			return printer.Secrets(secrets, format())
		},
	}
	list.Flags().StringVar(&listStore, "store", "", "Only this Store")

	var getKey, getVersion string
	get := &cobra.Command{
		Use:   "get <ID>",
		Short: "Show a secret's VALUE. Audited as a reveal",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := dial()
			if err != nil {
				return err
			}
			var key, version *string
			if cmd.Flags().Changed("key") {
				key = &getKey
			}
			if cmd.Flags().Changed("version") {
				version = &getVersion
			}
			value, err := client.Reveal(cmd.Context(), args[0], key, version)
			if err != nil {
				return err
			}
			// Deliberately bare on stdout: a value is usually being piped,
			// and wrapping it in JSON by default would mean every caller
			// unwraps.
			return printer.Value(value, format())
		},
	}
	get.Flags().StringVarP(&getKey, "key", "k", "", "One key of a key/value secret")
	get.Flags().StringVar(&getVersion, "version", "", "A particular version; the latest by default")

	view := &cobra.Command{
		Use: "view <ID>",
		Short: "Show a secret's metadata. NOT a reveal, and not audited as one — " +
			"which is why it is a separate command rather than a flag on `get`",
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := dial()
			if err != nil {
				return err
			}
			secret, err := client.View(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printer.Secret(secret, format())
		},
	}

	var createStore, createName, createValue, createNote string
	create := &cobra.Command{
		Use:   "create",
		Short: "Bring a new secret into the inventory",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := required(cmd, "store", "name", "value"); err != nil {
				return err
			}
			client, err := dial()
			if err != nil {
				return err
			}
			value, err := readValue(cmd.InOrStdin(), createValue)
			if err != nil {
				return err
			}
			secret, err := client.Create(cmd.Context(), createStore, createName, value, createNote)
			if err != nil {
				return err
			}
			return printer.Secret(secret, format())
		},
	}
	create.Flags().StringVar(&createStore, "store", "", "")
	create.Flags().StringVar(&createName, "name", "", "")
	create.Flags().StringVar(&createValue, "value", "",
		"The value. `-` reads stdin, which is how a value stays out of shell history")
	create.Flags().StringVar(&createNote, "note", "", "")

	var patchValue, patchNote string
	patch := &cobra.Command{
		Use:   "patch <ID>",
		Short: "Write a new version of a secret",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := required(cmd, "value"); err != nil {
				return err
			}
			client, err := dial()
			if err != nil {
				return err
			}
			value, err := readValue(cmd.InOrStdin(), patchValue)
			if err != nil {
				return err
			}
			version, err := client.Patch(cmd.Context(), args[0], value, patchNote)
			if err != nil {
				return err
			}
			return printer.Version(version, format())
		},
	}
	patch.Flags().StringVar(&patchValue, "value", "", "The value. `-` reads stdin")
	patch.Flags().StringVar(&patchNote, "note", "", "")

	var (
		delegateUser  string
		delegateGroup string
		delegateLevel string
		delegateKeys  []string
		delegateDays  int64
		delegateNote  string
	)
	delegate := &cobra.Command{
		Use:   "delegate <ID>",
		Short: "Grant sight of a secret to somebody",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("user") && cmd.Flags().Changed("group") {
				return usageError{errors.New("--user cannot be used with --group")}
			}
			client, err := dial()
			if err != nil {
				return err
			}
			var kind, subject string
			switch {
			case cmd.Flags().Changed("user"):
				kind, subject = "user", delegateUser
			case cmd.Flags().Changed("group"):
				kind, subject = "group", delegateGroup
			default:
				return errors.New("give exactly one of --user or --group")
			}
			grant, err := client.Delegate(cmd.Context(), args[0], wire.NewGrant{
				Kind:    kind,
				Subject: subject,
				Level:   delegateLevel,
				Keys:    delegateKeys,
				Days:    delegateDays,
				Note:    delegateNote,
			})
			if err != nil {
				return err
			}
			return printer.Grant(grant, format())
		},
	}
	delegate.Flags().StringVar(&delegateUser, "user", "", "A person's handle")
	delegate.Flags().StringVar(&delegateGroup, "group", "", "A group, as the identity provider spells it")
	delegate.Flags().StringVar(&delegateLevel, "level", "read", "guest, read or write")
	delegate.Flags().StringArrayVar(&delegateKeys, "key", nil,
		"Limit the grant to these keys of a key/value secret")
	delegate.Flags().Int64Var(&delegateDays, "days", 0, "Expire the grant after this many days")
	delegate.Flags().StringVar(&delegateNote, "note", "", "")

	login := &cobra.Command{
		Use:   "login <URL>",
		Short: "Sign in: opens the console to mint a token, and saves it",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return profile.Login(cmd.InOrStdin(), stdout, args[0])
		},
	}

	root.AddCommand(list, get, view, create, patch, delegate, login)
	return root
}

// readValue: `-` reads stdin, so a value never has to appear in shell history
// or in a process listing.
func readValue(in io.Reader, given string) (string, error) {
	if given != "-" {
		return given, nil
	}
	buffer, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(buffer), "\n"), nil
}

func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageError{err}
	}
	return nil
}

func exactArgs(count int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(count)(cmd, args); err != nil {
			return usageError{err}
		}
		return nil
	}
}

// required reports flags that were not given. By hand rather than through
// cobra's MarkFlagRequired, so the mistake carries the usage exit code.
func required(cmd *cobra.Command, names ...string) error {
	var missing []string
	for _, name := range names {
		if !cmd.Flags().Changed(name) {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return usageError{fmt.Errorf(
		"the following required flags were not provided: %s", strings.Join(missing, ", "))}
}
