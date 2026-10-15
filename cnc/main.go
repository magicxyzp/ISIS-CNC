package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"isis-cc/core"
)

// ANSI helpers
const (
	clReset  = "\033[0m"
	clBold   = "\033[1m"
	clDim    = "\033[2m"
	clWhite  = "\033[97m"
	clGray   = "\033[90m"
	clGreen  = "\033[92m"
	clRed    = "\033[91m"
	clYellow = "\033[93m"
	clCyan   = "\033[96m"
)

func info(msg string)  { fmt.Printf("  %s•%s %s\n", clCyan, clReset, msg) }
func ok(msg string)    { fmt.Printf("  %s✓%s %s\n", clGreen, clReset, msg) }
func warn(msg string)  { fmt.Printf("  %s⚠%s %s%s%s\n", clYellow, clReset, clYellow, msg, clReset) }
func fatal(msg string) { fmt.Printf("  %s✗%s %s%s%s\n", clRed, clReset, clRed, msg, clReset) }

func printBanner() {
	fmt.Println()
	fmt.Printf("  %s%s██╗███████╗██╗███████╗%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s██║██╔════╝██║██╔════╝%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s██║███████╗██║███████╗%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s██║╚════██║██║╚════██║%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s██║███████║██║███████║%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s╚═╝╚══════╝╚═╝╚══════╝%s\n", clBold, clWhite, clReset)
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", clDim, clGray, clReset)
	fmt.Println()
}

func printSection(label string) {
	fmt.Printf("\n%s%s%s%s\n", clDim, clGray, label, clReset)
}

func main() {
	core.EnableANSI()
	printBanner()

	printSection("STARTUP")

	if !core.ChdirToProjectWithAssets() {
		warn("assets/config.json not found from cwd or near executable — banners may fail")
	}

	configPath := "assets/config.json"
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		fatal(fmt.Sprintf("Failed to load config: %v", err))
		os.Exit(1)
	}
	ok("Config loaded")

	db, err := core.NewDatabase(cfg.Database)
	if err != nil {
		fatal(fmt.Sprintf("Database connection failed: %v", err))
		os.Exit(1)
	}
	defer db.Close()
	ok("Database connected")

	os.MkdirAll("assets/logs", 0755)

	attacks := core.NewAttackManager(cfg, db)
	webhooks := core.NewWebhookManager(cfg.Webhooks)

	printSection("LOADED")
	info(fmt.Sprintf("%-18s %s%d%s", "Attack methods", clWhite, len(cfg.Attacks), clReset))
	info(fmt.Sprintf("%-18s %s%d%s", "Themes", clWhite, len(cfg.Themes), clReset))
	info(fmt.Sprintf("%-18s %s%d%s", "Presets", clWhite, len(cfg.Presets), clReset))

	printSection("SERVICES")

	// Compute addresses for display
	sshAddr := cfg.ServerConfig.ResolveSSHListenAddr()

	websiteAddr := ""
	if cfg.Website.Enabled {
		wsIP := cfg.ServerConfig.ResolveSSHBindHost()
		wsPort := cfg.Website.Port
		if wsPort <= 0 {
			wsPort = 8081
		}
		websiteAddr = fmt.Sprintf("%s:%d", wsIP, wsPort)
	}

	apiAddr := ""
	if cfg.API.Enabled && strings.TrimSpace(cfg.API.ListenAddr) != "" {
		apiAddr = cfg.API.ListenAddr
	}

	svcLine := fmt.Sprintf("SSH %-22s", sshAddr)
	if apiAddr != "" {
		svcLine += fmt.Sprintf("  HTTP API %-20s", apiAddr)
	} else {
		svcLine += fmt.Sprintf("  HTTP API %-20s", "disabled")
	}
	if websiteAddr != "" {
		svcLine += fmt.Sprintf("  Website %s", websiteAddr)
	} else {
		svcLine += "  Website disabled"
	}
	info(svcLine)
	if apiAddr != "" {
		info(fmt.Sprintf("%-18s %sGET/POST /api/attack · GET /api/ongoing%s (JSON, add ?compact=1 for one line)", "API routes", clDim, clReset))
	}

	server := core.NewServer(cfg, db, attacks, webhooks, configPath)
	core.StartAPIServer(server, db, attacks, webhooks)
	core.StartWebsiteServer(cfg)

	go server.WatchConfigAutoReload()

	fmt.Println()
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", clDim, clGray, clReset)

	if err := server.Start(); err != nil {
		fatal(fmt.Sprintf("Server error: %v", err))
		os.Exit(1)
	}
}
