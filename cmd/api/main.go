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
	//
	// The config type is a closed list, so an unknown word was already
	// refused when the file was read; the switch here is over what this build
	// can construct, and the default is the compiler's reminder to add a case
	// when a kind is added.
	var directory identityservice.Directory
	switch cfg.Oidc.Directory {
	case config.DirectoryNone:
	case config.DirectoryKeycloak:
		keycloak, err := identityinfra.NewKeycloakDirectory(
			cfg.Oidc.Issuer, cfg.Oidc.ClientID, cfg.Oidc.ClientSecret)
		if err != nil {
			return err
		}
		// The staleness window is the identity domain's policy; the Keycloak
		// client itself asks the realm every time it is called.
		directory = identityservice.NewCachedDirectory(
			keycloak, identityservice.DefaultStaleness, time.Now)
		slog.Info("directory configured; token holders are checked live",
			"staleness", identityservice.DefaultStaleness)
	default:
		return &config.UnknownDirectoryError{Kind: string(cfg.Oidc.Directory)}
	}
	identityService := identityservice.NewService(identityinfra.NewPostgresIdentityRepo(db), directory)

	// Discovered at boot: a console that only reaches its issuer when somebody
	// tries to sign in is one that looks healthy while being unusable.
	//
	// The interface is left nil when there is no issuer, rather than holding
	// a nil *Oidc: a typed nil inside an interface is not nil, and every
	// sign-in route decides dev mode by comparing this against nil.
	var issuer identityservice.Issuer
	if cfg.Oidc.Issuer != "" {
		discovered, err := identityinfra.Discover(ctx, cfg.Oidc)
		if err != nil {
			return err
		}
		issuer = discovered
	}

	// Every Store call reports through the metrics, passed in by name like
	// every other dependency.
	stores, err := mountStores(ctx, cfg, db, tel.BackendCall)
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
	//
	// Which words in dev_roles name a role is the identity domain's
	// judgement, not this file's: NewDevActor keeps the unknown ones out and
	// says so out loud.
	var dev *identityservice.DevActor
	if issuer == nil {
		parsed := identityservice.NewDevActor(cfg.Oidc.DevUser, cfg.Oidc.DevRoles, cfg.Oidc.DevGroups)
		dev = &parsed
		slog.Warn("no issuer configured; serving as the dev user with no authentication",
			"user", dev.Handle.String())
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
		Oidc:         issuer,
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
// Each case reads the settings ITS kind needs, through config's typed
// getters: the `.(string)` assertions and the hand-rolled "needs a `project`"
// sentences that used to be inline here were configuration decoding wearing a
// switch statement, and they belong with the rest of the config schema.
//
// A Store whose adapter this build does not know never reaches here — the
// config refuses the word — but the default case stands, because a kind added
// to config and not to this switch is exactly the mistake worth failing the
// process over: silently serving four of five declared Stores is worse than
// not starting, since nobody notices the fifth is missing.
func mountStores(
	ctx context.Context, cfg config.Config, db *sqlx.DB, observe secretsservice.BackendObserver,
) (*secretsservice.Registry, error) {
	mounted := make([]*secretsservice.Store, 0, len(cfg.Stores))
	for _, declared := range cfg.Stores {
		var manager secretsentity.SecretManager
		switch declared.Kind {
		case config.KindKeyway:
			keyring, err := secretsservice.KeyringFor(declared)
			if err != nil {
				return nil, err
			}
			manager = secretsservice.NewOwnStoreService(
				declared.ID, secretsinfra.NewPostgresOwnStoreRepo(db), keyring)
		case config.KindGcp:
			settings, err := declared.GcpSettings()
			if err != nil {
				return nil, err
			}
			gcp, err := secretsinfra.NewGcpSecretManager(ctx, settings.Project)
			if err != nil {
				return nil, err
			}
			manager = gcp
		case config.KindYc:
			settings, err := declared.YcSettings()
			if err != nil {
				return nil, err
			}
			manager = secretsinfra.NewYcLockbox(settings.Folder, settings.Secret)
		case config.KindAws:
			settings, err := declared.AwsSettings()
			if err != nil {
				return nil, err
			}
			aws, err := secretsinfra.NewAwsSecretsManager(ctx, settings.Region)
			if err != nil {
				return nil, err
			}
			manager = aws
		case config.KindK8s:
			settings, err := declared.K8sSettings()
			if err != nil {
				return nil, err
			}
			if declared.Select.IsEmpty() {
				// Not fatal, but a Store showing every service-account token in
				// a namespace is one nobody wanted.
				slog.Warn("no `select` on a kubernetes store; "+
					"every Secret in the namespace will be listed", "store", declared.ID.String())
			}
			k8s, err := secretsinfra.NewKubernetesSecrets(settings.Namespace)
			if err != nil {
				return nil, err
			}
			manager = k8s
		default:
			return nil, &config.UnknownStoreKindError{
				Store: declared.ID.String(), Kind: declared.Kind.String(),
			}
		}
		mounted = append(mounted, secretsservice.NewStore(declared, manager, observe))
	}
	return secretsservice.NewRegistry(mounted)
}
