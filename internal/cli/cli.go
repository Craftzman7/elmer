// Package cli implements elmer's command line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"elmer/internal/app"
	"elmer/internal/config"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "elmer",
		Short: "Blue team host monitor for Red v Blue competitions",
		Long: `elmer watches a host for attacker activity: process execution,
authentication, file integrity, network connections, and persistence
mechanisms. It alerts via Discord, ntfy, or any webhook. It never opens
listening sockets.

Run from an elevated terminal. On Linux, root enables eBPF tracing with
full argv capture; without it elmer falls back to netlink or /proc polling.`,
		SilenceUsage: true,
	}
	root.AddCommand(startCmd(), auditCmd(), testAlertsCmd(), initConfigCmd(), hardenCmd(), versionCmd())
	return root
}

func auditCmd() *cobra.Command {
	var cfgPath string
	var writeBaseline bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "One-shot report of the persistence surface (users, SUID, systemd, cron, keys)",
		RunE: func(*cobra.Command, []string) error {
			cfg, _, err := app.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			return app.Audit(cfg, writeBaseline)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&writeBaseline, "write-baseline", false,
		"store this state as the persistence baseline")
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the elmer version",
		Run:   func(*cobra.Command, []string) { fmt.Println("elmer", Version) },
	}
}

func startCmd() *cobra.Command {
	var cfgPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run all monitors and alert until interrupted",
		RunE: func(*cobra.Command, []string) error {
			cfg, path, err := app.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			return app.Run(cfg, jsonOut, path)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "NDJSON output for jq piping")
	return cmd
}

func testAlertsCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "test-alerts",
		Short: "Send a synthetic alert through every configured channel",
		RunE: func(*cobra.Command, []string) error {
			cfg, _, err := app.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			fmt.Println("sending test alert to:", alertChannels(cfg))
			return app.TestAlerts(cfg)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "config file path")
	return cmd
}

func alertChannels(cfg *config.Config) []string {
	var out []string
	if cfg.Alerts.Discord.URL != "" {
		out = append(out, "discord")
	}
	if cfg.Alerts.Ntfy.Topic != "" {
		out = append(out, "ntfy")
	}
	if cfg.Alerts.Webhook.URL != "" {
		out = append(out, "webhook")
	}
	if len(out) == 0 {
		out = append(out, "(none configured)")
	}
	return out
}

func initConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-config [path]",
		Short: "Write a commented default config",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path := "elmer.yaml"
			if len(args) == 1 {
				path = args[0]
			}
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists", path)
			}
			if err := os.WriteFile(path, []byte(config.DefaultYAML), 0o600); err != nil {
				return err
			}
			fmt.Println("wrote", path)
			return nil
		},
	}
	return cmd
}

func hardenCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "harden",
		Short: "Print platform steps to maximize elmer's telemetry",
		RunE: func(*cobra.Command, []string) error {
			cfg, _, err := app.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			return app.Harden(cfg)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "config file path")
	return cmd
}
