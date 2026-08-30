// The keyway backend, being ported from Rust (ADR-0006).
//
// keywayd rather than keyway, because the user-facing name belongs to the
// CLI: people type `keyway` at a shell, while nothing types the server's name
// but a Dockerfile.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kotsmile/keyway/internal/config"
	"github.com/kotsmile/keyway/internal/infra/postgres"
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
