package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/core"
	"github.com/routewarden/tcp-warden/plugins"
	_ "github.com/routewarden/tcp-warden/plugins/all"
)

var (
	version = "1.0.0"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		runDaemon("tcp-warden.yaml")
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		handleRun(args)
	case "validate":
		handleValidate(args)
	case "status":
		handleStatus(args)
	case "plugins":
		handlePlugins(args)
	case "banlist":
		handleBanlist(args)
	case "unban":
		handleUnban(args)
	case "ban":
		handleBan(args)
	case "version", "--version", "-v":
		fmt.Printf("tcp-warden version %s (commit: %s, date: %s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		if strings.HasPrefix(cmd, "-") {
			handleRun(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`RouteWarden TCP Warden - Protocol-Aware L4 Security Proxy

Usage:
  tcp-warden [command] [flags]

Commands:
  run         Start the TCP security proxy daemon (default)
  validate    Verify YAML configuration syntax and rules
  plugins     Manage and test modular protocol plugins
  status      Query health and metrics from running daemon
  banlist     Display active IP bans
  unban       Remove an active IP ban
  ban         Manually ban an IP address
  version     Display version information
  help        Show this help message

Run Flags:
  --config, -c   Path to YAML config file (default: tcp-warden.yaml)

Examples:
  tcp-warden run --config tcp-warden.yaml
  tcp-warden validate --config tcp-warden.yaml
  tcp-warden plugins list
  tcp-warden plugins test
  tcp-warden status --api http://127.0.0.1:9091
  tcp-warden banlist --api http://127.0.0.1:9091
  tcp-warden unban 192.0.2.1 --api http://127.0.0.1:9091
  tcp-warden ban 198.51.100.42 --duration 2h --reason "brute_force" --api http://127.0.0.1:9091
`)
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "tcp-warden.yaml", "Path to YAML config file")
	fs.StringVar(configPath, "c", "tcp-warden.yaml", "Path to YAML config file")
	_ = fs.Parse(args)

	runDaemon(*configPath)
}

func runDaemon(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error loading configuration %s: %v\n", configPath, err)
		os.Exit(1)
	}

	fmt.Println("🛡️  Starting RouteWarden TCP Warden...")
	fmt.Printf("   Config: %s\n", configPath)
	fmt.Printf("   Services (%d):\n", len(cfg.Services))
	for name, svc := range cfg.Services {
		status := "enabled"
		if !svc.IsEnabled() {
			status = "disabled"
		}
		fmt.Printf("     • %-12s [%s]  %s -> %s (%s)\n", name, svc.Protocol, svc.Listen, svc.Upstream, status)
	}

	if cfg.API.Enabled {
		fmt.Printf("   API listen: %s\n", cfg.API.Listen)
	}
	if cfg.CrowdSec.Enabled {
		fmt.Printf("   CrowdSec:   %s (sync every %s)\n", cfg.CrowdSec.LAPIURL, cfg.CrowdSec.UpdateFrequency.Duration())
	}
	if cfg.Global.LogFile != "" {
		fmt.Printf("   Log file:   %s\n", cfg.Global.LogFile)
	}

	d, err := core.NewDaemon(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error initializing daemon: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Shutting down TCP Warden...")
		cancel()
	}()

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Daemon error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ TCP Warden shut down gracefully.")
}

func handleValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "tcp-warden.yaml", "Path to YAML config file")
	fs.StringVar(configPath, "c", "tcp-warden.yaml", "Path to YAML config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Configuration %s is VALID.\n", *configPath)
	fmt.Printf("  - Version: %s\n", cfg.Version)
	fmt.Printf("  - Active services: %d\n", len(cfg.Services))
	for name, svc := range cfg.Services {
		fmt.Printf("    • %s: %s -> %s [%s]\n", name, svc.Listen, svc.Upstream, svc.Protocol)
	}
	fmt.Printf("  - Management API: %t (%s)\n", cfg.API.Enabled, cfg.API.Listen)
	fmt.Printf("  - CrowdSec bouncer: %t\n", cfg.CrowdSec.Enabled)
	fmt.Printf("  - SIEM log file: %s\n", cfg.Global.LogFile)
}

func handleStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	_ = fs.Parse(args)

	url := strings.TrimRight(*apiAddr, "/") + "/health"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon at %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(body))
	}
}

func handleBanlist(args []string) {
	fs := flag.NewFlagSet("banlist", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	_ = fs.Parse(args)

	url := strings.TrimRight(*apiAddr, "/") + "/api/banlist"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var bans []core.BanEntry
	if err := json.NewDecoder(resp.Body).Decode(&bans); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to decode banlist: %v\n", err)
		os.Exit(1)
	}

	if len(bans) == 0 {
		fmt.Println("No active bans.")
		return
	}

	fmt.Printf("%-18s %-20s %-12s %-22s %s\n", "IP", "REASON", "SERVICE", "BANNED AT", "EXPIRES IN")
	fmt.Println(strings.Repeat("-", 85))
	for _, b := range bans {
		expiresIn := "permanent"
		if !b.Permanent {
			rem := time.Until(b.ExpiresAt).Round(time.Second)
			if rem > 0 {
				expiresIn = rem.String()
			} else {
				expiresIn = "expired"
			}
		}
		fmt.Printf("%-18s %-20s %-12s %-22s %s\n",
			b.IP,
			truncate(b.Reason, 20),
			b.Service,
			b.BannedAt.Format("2006-01-02 15:04:05"),
			expiresIn,
		)
	}
}

func handleUnban(args []string) {
	fs := flag.NewFlagSet("unban", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	_ = fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden unban <ip> [--api <url>]")
		os.Exit(1)
	}
	ip := fs.Args()[0]

	url := strings.TrimRight(*apiAddr, "/") + "/api/unban"
	bodyBytes, _ := json.Marshal(map[string]string{"ip": ip})
	resp, err := http.Post(url, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result struct {
		Unbanned bool   `json:"unbanned"`
		IP       string `json:"ip"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Unbanned {
		fmt.Printf("✓ Successfully unbanned %s\n", ip)
	} else {
		fmt.Printf("ℹ IP %s was not in the active banlist\n", ip)
	}
}

func handleBan(args []string) {
	fs := flag.NewFlagSet("ban", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	reason := fs.String("reason", "manual_admin_ban", "Reason for the ban")
	duration := fs.String("duration", "1h", "Duration of the ban (e.g. '1h', '30m')")
	_ = fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden ban <ip> [--duration 1h] [--reason \"...\"] [--api <url>]")
		os.Exit(1)
	}
	ip := fs.Args()[0]

	url := strings.TrimRight(*apiAddr, "/") + "/api/ban"
	bodyBytes, _ := json.Marshal(map[string]string{
		"ip":       ip,
		"reason":   *reason,
		"duration": *duration,
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("✓ Successfully banned %s for %s (%s)\n", ip, *duration, *reason)
	} else {
		fmt.Fprintf(os.Stderr, "❌ Ban failed with status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func handlePlugins(args []string) {
	if len(args) == 0 {
		printPluginsUsage()
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		handlePluginsList()
	case "test":
		handlePluginsTest(subargs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugins subcommand: %s\n\n", subcmd)
		printPluginsUsage()
		os.Exit(1)
	}
}

func printPluginsUsage() {
	fmt.Print(`RouteWarden TCP Warden - Modular Protocol Plugins

Usage:
  tcp-warden plugins [command]

Commands:
  list        List all registered plugins and their self-test health status
  test [name] Execute synthetic self-tests on registered plugins

Examples:
  tcp-warden plugins list
  tcp-warden plugins test
  tcp-warden plugins test postgres
`)
}

func handlePluginsList() {
	plugins.RunSelfTests()
	list := plugins.List()
	fmt.Printf("%-14s %-9s %-12s %-22s %s\n", "PLUGIN", "VERSION", "STATUS", "PROTOCOLS", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 95))
	for _, p := range list {
		statusStr := string(p.Status)
		if p.Status == plugins.StatusActive {
			statusStr = "✓ ACTIVE"
		} else if p.Status == plugins.StatusDisabled {
			statusStr = "✗ DISABLED"
		}
		fmt.Printf("%-14s %-9s %-12s %-22s %s\n",
			p.Name,
			p.Version,
			statusStr,
			strings.Join(p.Protocols, ", "),
			truncate(p.Description, 36),
		)
	}
}

func handlePluginsTest(args []string) {
	fmt.Println("🧪 Executing RouteWarden Plugin Self-Tests...")
	target := ""
	if len(args) > 0 {
		target = args[0]
	}

	if target != "" {
		res, err := plugins.Global().RunSelfTest(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error testing plugin %q: %v\n", target, err)
			os.Exit(1)
		}
		if res.Passed {
			fmt.Printf("✓ %-14s - PASSED (%v)\n", res.PluginName, res.Duration)
		} else {
			fmt.Printf("✗ %-14s - FAILED (%v): %v\n", res.PluginName, res.Duration, res.Error)
			os.Exit(1)
		}
		return
	}

	results := plugins.RunSelfTests()
	var names []string
	for k := range results {
		names = append(names, k)
	}
	sort.Strings(names)

	passedCount := 0
	failedCount := 0

	for _, name := range names {
		res := results[name]
		if res.Passed {
			passedCount++
			fmt.Printf("  ✓ %-14s - PASSED (%v)\n", res.PluginName, res.Duration)
		} else {
			failedCount++
			fmt.Printf("  ✗ %-14s - FAILED (%v): %v\n", res.PluginName, res.Duration, res.Error)
		}
	}

	fmt.Println()
	if failedCount > 0 {
		fmt.Printf("⚠️ Results: %d passed, %d failed. Failed plugins have been automatically disabled.\n", passedCount, failedCount)
		os.Exit(1)
	} else {
		fmt.Printf("✓ Results: %d/%d passed. All registered plugins healthy and active.\n", passedCount, passedCount)
	}
}
