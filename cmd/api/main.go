// The keyway backend, ported from Rust (ADR-0006).
//
// The directory is cmd/api; the binary it builds is `keywayd` (go build -o
// keywayd ./cmd/api). keywayd rather than keyway, because the user-facing
// name belongs to the CLI: people type `keyway` at a shell, while nothing
// types the server's name but a Dockerfile.
//
// This file is the binding place: the cobra tree, and a serve() where every
// infra client and every service is constructed explicitly — the Rust
// main.rs serve() carried over, with the container's Arc-typed wiring
// flattened into plain struct fields, which is what Go's pointers already
// are.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/kotsmile/keyway/config"
	accessinfra "github.com/kotsmile/keyway/internal/access/infra"
	accessservice "github.com/kotsmile/keyway/internal/access/service"
	auditinfra "github.com/kotsmile/keyway/internal/audit/infra"
	auditservice "github.com/kotsmile/keyway/internal/audit/service"
	identityentity "github.com/kotsmile/keyway/internal/identity/entity"
	identityinfra "github.com/kotsmile/keyway/internal/identity/infra"
	identityservice "github.com/kotsmile/keyway/internal/identity/service"
	"github.com/kotsmile/keyway/internal/postgres"
	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
	secretsinfra "github.com/kotsmile/keyway/internal/secrets/infra"
	secretsservice "github.com/kotsmile/keyway/internal/secrets/service"
	"github.com/kotsmile/keyway/internal/telemetry"
	tokensinfra "github.com/kotsmile/keyway/internal/tokens/infra"
	tokensservice "github.com/kotsmile/keyway/internal/tokens/service"
	keywayhttp "github.com/kotsmile/keyway/internal/transport/http"
)

func main() {
	var configPath string

	root := &cobra.Command{
		Use:          "keywayd",
		Short:        "A secrets console over the secret managers you already run",
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "config.yml",
		"The single file this deployment is configured by")

	root.AddCommand(&cobra.Command{
		Use:   "migrate",
		Short: "Bring the schema up to date",
		Long: "Bring the schema up to date.\n\n" +
			"Its own command rather than something `serve` does: three replicas\n" +
			"racing to migrate during a rolling deploy fail in a way nobody can\n" +
			"reproduce.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			db, err := postgres.Connect(cmd.Context(), cfg.Postgres)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := postgres.Migrate(cmd.Context(), db); err != nil {
				return err
			}
			fmt.Println("schema is up to date")
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			return serve(cmd.Context(), cfg)
		},
	})

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// serve runs the HTTP service until a signal stops it.
func serve(ctx context.Context, cfg config.Config) error {
	tel, err := telemetry.Init(ctx, cfg.Telemetry.ServiceName, cfg.Telemetry.OtlpEndpoint)
	if err != nil {
		return err
	}
	defer func() {
		// A bounded flush on the way out: a shutdown should not be the last
		// thing lost, but it should not hang on a dead collector either.
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tel.Shutdown(flushCtx)
	}()
	// Every Store call reports through the metrics, from boot onward.
	secretsservice.ObserveBackendCall = tel.BackendCall

	db, err := postgres.Connect(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	accessService := accessservice.NewService(accessinfra.NewPostgresAccessRepo(db))
	auditService := auditservice.NewService(auditinfra.NewPostgresAuditRepo(db))
	tokenService := tokensservice.NewService(tokensinfra.NewPostgresTokenRepo(db))

	// Without a Directory, a token's groups are what keyway remembered at its
	// holder's last sign-in, and deleting a token is the only revocation.
	var directory identityservice.Directory
	switch cfg.Oidc.Directory {
	case "":
	case "keycloak":
		keycloak, err := identityinfra.NewKeycloakDirectory(
			cfg.Oidc.Issuer, cfg.Oidc.ClientID, cfg.Oidc.ClientSecret)
		if err != nil {
			return err
		}
		directory = keycloak
	default:
		return fmt.Errorf(
			"oidc.directory names an unknown kind %q; this build has: keycloak",
			cfg.Oidc.Directory)
	}
	if directory != nil {
		slog.Info("directory configured; token holders are checked live")
	}
	identityService := identityservice.NewService(identityinfra.NewPostgresIdentityRepo(db), directory)

	// Discovered at boot: a console that only reaches its issuer when somebody
	// tries to sign in is one that looks healthy while being unusable.
	var oidc *identityinfra.Oidc
	if cfg.Oidc.Issuer != "" {
		oidc, err = identityinfra.Discover(ctx, cfg.Oidc)
		if err != nil {
			return err
		}
	}

	stores, err := mountStores(ctx, cfg, db)
	if err != nil {
		return err
	}
	slog.Info("stores mounted", "count", stores.Len())

	codec, err := sessionCodec(cfg)
	if err != nil {
		return err
	}

	// Dev mode is on precisely when no issuer is configured. Every
	// authorisation decision is still made, so a local run behaves like
	// production minus the redirect.
	var dev *keywayhttp.DevActor
	if oidc == nil {
		dev = devActor(cfg)
		slog.Warn("no issuer configured; serving as the dev user with no authentication",
			"user", dev.Handle)
	}

	state := &keywayhttp.State{
		Stores:   stores,
		Access:   accessService,
		Audit:    auditService,
		Tokens:   tokenService,
		Identity: identityService,
		Auth: &keywayhttp.Auth{
			Tokens:   tokenService,
			Identity: identityService,
			Dev:      dev,
			Codec:    codec,
		},
		Branding:     cfg.Branding,
		Oidc:         oidc,
		SessionHours: cfg.Oidc.SessionHours,
		Codec:        codec,
	}

	// Two listeners, because a scrape endpoint publishes what a deployment
	// holds and is almost always less guarded than an API port.
	api := &http.Server{
		Addr:              normalise(cfg.Server.Address),
		Handler:           keywayhttp.Build(state),
		ReadHeaderTimeout: 10 * time.Second,
	}
	metrics := &http.Server{
		Addr:              normalise(cfg.Server.MetricsAddress),
		Handler:           keywayhttp.Metrics(tel.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("listening", "api", cfg.Server.Address, "metrics", cfg.Server.MetricsAddress)

	return run(ctx, api, metrics)
}

// run serves both listeners until a signal, then stops accepting and lets
// in-flight requests finish. A reveal cut in half is an audit row without an
// answer.
func run(ctx context.Context, servers ...*http.Server) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	group, groupCtx := errgroup.WithContext(ctx)
	for _, server := range servers {
		group.Go(func() error {
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
	}
	group.Go(func() error {
		<-groupCtx.Done()
		slog.Info("shutting down")
		drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var failed error
		for _, server := range servers {
			if err := server.Shutdown(drain); err != nil {
				failed = errors.Join(failed, err)
			}
		}
		return failed
	})
	return group.Wait()
}

// sessionCodec is the key the session cookie is encrypted under.
//
// Generated when unset, which is right for a single-replica dev run and wrong
// for anything else — several replicas each generating their own means a
// session minted by one is unreadable by the next, so this warns loudly.
func sessionCodec(cfg config.Config) (*keywayhttp.Codec, error) {
	if cfg.Oidc.SessionKey == "" {
		slog.Warn("no oidc.session_key configured; generating one. " +
			"Sessions will not survive a restart, and replicas will not share them.")
		return keywayhttp.NewCodec(keywayhttp.GenerateKey())
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Oidc.SessionKey))
	if err != nil {
		return nil, fmt.Errorf("oidc.session_key is not base64: %w", err)
	}
	return keywayhttp.NewCodec(raw)
}

// devActor is who a local run acts as, from the dev_* config.
func devActor(cfg config.Config) *keywayhttp.DevActor {
	handle := cfg.Oidc.DevUser
	if handle == "" {
		handle = "dev"
	}
	roles := make([]identityentity.Role, 0, len(cfg.Oidc.DevRoles))
	for _, word := range cfg.Oidc.DevRoles {
		if role, known := identityentity.ParseRole(word); known {
			roles = append(roles, role)
		}
	}
	return &keywayhttp.DevActor{Handle: handle, Roles: roles, Groups: cfg.Oidc.DevGroups}
}

// normalise: `:8080` is how a config spells "every interface", which the Rust
// server bound as 0.0.0.0. Go would accept the bare form, but binding what
// Rust bound keeps a deployment's firewall assumptions intact.
func normalise(address string) string {
	if strings.HasPrefix(address, ":") {
		return "0.0.0.0" + address
	}
	return address
}

// mountStores builds every Store the config declares.
//
// A Store whose adapter this build does not know is worth refusing to start
// over: silently serving four of five declared Stores is worse than not
// starting, because nobody notices the fifth is missing.
func mountStores(ctx context.Context, cfg config.Config, db *sqlx.DB) (*secretsservice.Registry, error) {
	mounted := make([]*secretsservice.Store, 0, len(cfg.Stores))
	for _, declared := range cfg.Stores {
		setting := func(name string) (string, bool) {
			value, ok := declared.Settings[name].(string)
			return value, ok
		}
		var manager secretsentity.SecretManager
		switch declared.Kind {
		case "keyway":
			keyring, err := secretsservice.KeyringFor(declared)
			if err != nil {
				return nil, err
			}
			manager = secretsservice.NewOwnStoreService(
				declared.ID, secretsinfra.NewPostgresOwnStoreRepo(db), keyring)
		case "gcp":
			project, ok := setting("project")
			if !ok {
				return nil, fmt.Errorf("store %q needs a `project`", declared.ID)
			}
			gcp, err := secretsinfra.NewGcpSecretManager(ctx, project)
			if err != nil {
				return nil, err
			}
			manager = gcp
		case "yc":
			folder, ok := setting("folder")
			if !ok {
				return nil, fmt.Errorf("store %q needs a `folder`", declared.ID)
			}
			secret, _ := setting("secret")
			manager = secretsinfra.NewYcLockbox(folder, secret)
		case "aws":
			region, _ := setting("region")
			aws, err := secretsinfra.NewAwsSecretsManager(ctx, region)
			if err != nil {
				return nil, err
			}
			manager = aws
		case "k8s":
			namespace, ok := setting("namespace")
			if !ok {
				return nil, fmt.Errorf("store %q needs a `namespace`", declared.ID)
			}
			if declared.Select.IsEmpty() {
				// Not fatal, but a Store showing every service-account token in
				// a namespace is one nobody wanted.
				slog.Warn("no `select` on a kubernetes store; "+
					"every Secret in the namespace will be listed", "store", declared.ID)
			}
			k8s, err := secretsinfra.NewKubernetesSecrets(namespace)
			if err != nil {
				return nil, err
			}
			manager = k8s
		default:
			return nil, fmt.Errorf(
				"store %q names an unknown type %q; this build has: keyway, gcp, yc, aws, k8s",
				declared.ID, declared.Kind)
		}
		mounted = append(mounted, secretsservice.NewStore(declared, manager))
	}
	return secretsservice.NewRegistry(mounted)
}
