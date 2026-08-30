// The serve wiring: every port gets its adapter, every listener its router.
//
// This file is the Rust main.rs serve() carried over — mount_stores,
// session_key, the dev actor, normalise and the shutdown signal — with the
// container's Arc-typed wiring flattened into plain struct fields, which is
// what Go's pointers already are.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/sync/errgroup"

	"github.com/kotsmile/keyway/internal/config"
	"github.com/kotsmile/keyway/internal/domains/access"
	accessinfra "github.com/kotsmile/keyway/internal/domains/access/infra"
	"github.com/kotsmile/keyway/internal/domains/audit"
	auditinfra "github.com/kotsmile/keyway/internal/domains/audit/infra"
	"github.com/kotsmile/keyway/internal/domains/identity"
	identityentity "github.com/kotsmile/keyway/internal/domains/identity/entity"
	identityinfra "github.com/kotsmile/keyway/internal/domains/identity/infra"
	"github.com/kotsmile/keyway/internal/domains/secrets"
	secretsentity "github.com/kotsmile/keyway/internal/domains/secrets/entity"
	secretsinfra "github.com/kotsmile/keyway/internal/domains/secrets/infra"
	"github.com/kotsmile/keyway/internal/domains/tokens"
	tokensinfra "github.com/kotsmile/keyway/internal/domains/tokens/infra"
	"github.com/kotsmile/keyway/internal/infra/postgres"
	"github.com/kotsmile/keyway/internal/infra/telemetry"
	"github.com/kotsmile/keyway/internal/router"
	"github.com/kotsmile/keyway/internal/transport"
)

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
	secrets.ObserveBackendCall = tel.BackendCall

	db, err := postgres.Connect(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	accessService := access.NewService(accessinfra.NewPostgresAccessRepo(db))
	auditService := audit.NewService(auditinfra.NewPostgresAuditRepo(db))
	tokenService := tokens.NewService(tokensinfra.NewPostgresTokenRepo(db))

	// Without a Directory, a token's groups are what keyway remembered at its
	// holder's last sign-in, and deleting a token is the only revocation.
	var directory identity.Directory
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
	identityService := identity.NewService(identityinfra.NewPostgresIdentityRepo(db), directory)

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
	var dev *transport.DevActor
	if oidc == nil {
		dev = devActor(cfg)
		slog.Warn("no issuer configured; serving as the dev user with no authentication",
			"user", dev.Handle)
	}

	state := &transport.State{
		Stores:   stores,
		Access:   accessService,
		Audit:    auditService,
		Tokens:   tokenService,
		Identity: identityService,
		Auth: &transport.Auth{
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
		Handler:           router.Build(state),
		ReadHeaderTimeout: 10 * time.Second,
	}
	metrics := &http.Server{
		Addr:              normalise(cfg.Server.MetricsAddress),
		Handler:           router.Metrics(tel.Handler()),
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
func sessionCodec(cfg config.Config) (*transport.Codec, error) {
	if cfg.Oidc.SessionKey == "" {
		slog.Warn("no oidc.session_key configured; generating one. " +
			"Sessions will not survive a restart, and replicas will not share them.")
		return transport.NewCodec(transport.GenerateKey())
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Oidc.SessionKey))
	if err != nil {
		return nil, fmt.Errorf("oidc.session_key is not base64: %w", err)
	}
	return transport.NewCodec(raw)
}

// devActor is who a local run acts as, from the dev_* config.
func devActor(cfg config.Config) *transport.DevActor {
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
	return &transport.DevActor{Handle: handle, Roles: roles, Groups: cfg.Oidc.DevGroups}
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
func mountStores(ctx context.Context, cfg config.Config, db *sqlx.DB) (*secrets.Registry, error) {
	mounted := make([]*secrets.Store, 0, len(cfg.Stores))
	for _, declared := range cfg.Stores {
		setting := func(name string) (string, bool) {
			value, ok := declared.Settings[name].(string)
			return value, ok
		}
		var manager secretsentity.SecretManager
		switch declared.Kind {
		case "keyway":
			keyring, err := secrets.KeyringFor(declared)
			if err != nil {
				return nil, err
			}
			manager = secrets.NewOwnStoreService(
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
		mounted = append(mounted, secrets.NewStore(declared, manager))
	}
	return secrets.NewRegistry(mounted)
}
