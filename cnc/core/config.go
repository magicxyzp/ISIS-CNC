package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerConfig   ServerConfig   `json:"server_config"`
	API            APIConfig      `json:"api"`
	Website        WebsiteConfig  `json:"website"`
	Database       DatabaseConfig `json:"database"`
	Settings       Settings       `json:"settings"`
	Webhooks       Webhooks       `json:"webhooks"`
	AttackSettings AttackSettings `json:"attack_settings"`
	MethodGroups   []MethodGroup  `json:"method_groups"`
	Presets        []Preset       `json:"presets"`
	Themes         []Theme        `json:"themes"`
	Banners        []BannerDef    `json:"banners"`
	Attacks        []AttackDef    `json:"attacks"`
}

type ServerConfig struct {
	SSHAddr    string `json:"ssh_addr"`
	SSHPort    int    `json:"ssh_port"`
	PrivateKey string `json:"private_key"`
}

// ResolveSSHListenAddr returns the TCP address for the SSH CNC listener.
// If ssh_addr already includes a port (host:port), it is used as-is and ssh_port is ignored.
// Otherwise the port is ssh_port, or 9900 when ssh_port is omitted or zero.
func (sc *ServerConfig) ResolveSSHListenAddr() string {
	addr := strings.TrimSpace(sc.SSHAddr)
	if addr == "" || addr == "YOUR SERVER IP HERE" {
		addr = "0.0.0.0"
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	port := sc.SSHPort
	if port <= 0 {
		port = 9900
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

// ResolveSSHBindHost returns the host part of ssh_addr for binding other services (e.g. website).
// When ssh_addr has no port, the full string is the host. Placeholders yield 0.0.0.0.
func (sc *ServerConfig) ResolveSSHBindHost() string {
	addr := strings.TrimSpace(sc.SSHAddr)
	if addr == "" || addr == "YOUR SERVER IP HERE" {
		return "0.0.0.0"
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func (sc *ServerConfig) validate() error {
	addr := strings.TrimSpace(sc.SSHAddr)
	_, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil && sc.SSHPort != 0 && (sc.SSHPort < 1 || sc.SSHPort > 65535) {
		return fmt.Errorf("server_config.ssh_port must be between 1 and 65535")
	}
	return nil
}

// APIConfig controls the HTTP attack API (GET /api/attack?...).
type APIConfig struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listen_addr"`
}

// WebsiteConfig controls the static landing page server.
// The web assets directory is fixed to "assets/web" — not configurable by customers.
type WebsiteConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
	Table    string `json:"table"`
}

type Settings struct {
	General          GeneralSettings     `json:"general"`
	Title            TitleSettings       `json:"title"`
	InfoRewrites     InfoRewrites        `json:"information_rewrites"`
	DisabledCommands []string            `json:"disabled_commands"`
	Developer        DeveloperSettings   `json:"developer"`
	MFA              MFASettings         `json:"mfa"`
	Login            LoginSettings       `json:"login"`
}

// LoginSettings controls SSH pre-authentication banner only (before password).
type LoginSettings struct {
	// SSHBanner is a path under assets/banners/default/ only (e.g. branding/ssh-prelogin.txt), sent as the SSH pre-auth banner before the password prompt. TermFX ok; use <<$general.name>>, <<$datetime>>, etc. — not user.* (no account yet). Empty = none.
	SSHBanner string `json:"ssh_banner"`
}

// SanitizedSSHBanner returns SSHBanner as a safe subpath under assets/banners/default/, or empty if invalid.
func (ls LoginSettings) SanitizedSSHBanner() string {
	return sanitizeThemeBannerSubpath(ls.SSHBanner)
}

func sanitizeThemeBannerSubpath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.Contains(p, "..") {
		return ""
	}
	p = strings.TrimLeft(p, `/\`)
	if p == "" {
		return ""
	}
	for _, r := range p {
		if r < 32 || r == ':' {
			return ""
		}
	}
	return strings.ReplaceAll(p, `\`, `/`)
}

// MFASettings configures TOTP (Google Authenticator). Per-user toggle is via users mfa <u> on|off.
type MFASettings struct {
	// When true, every account must complete TOTP at SSH login (after password).
	ForceAllUsers bool `json:"force_all_users"`
	// Issuer name shown in the authenticator app (otpauth label). Defaults to settings.general.name or "ISIS-CNC".
	Issuer string `json:"issuer"`
	// VerifyBanner: theme-relative path (e.g. branding/mfa-verify.txt). TermFX; shown after password when entering a TOTP code. Empty = built-in text only.
	VerifyBanner string `json:"verify_banner"`
	// EnrollBanner: theme-relative path shown before the QR when the user must link an authenticator. Empty = built-in text only.
	EnrollBanner string `json:"enroll_banner"`
	// CodePrompt: line prefix before ReadLine for the 6-digit code (SGR 0;97m applied). Empty = "Authenticator code: ".
	CodePrompt string `json:"code_prompt"`
}

// SanitizedMFAVerifyBanner returns VerifyBanner as a safe theme-relative subpath, or empty if invalid.
func (ms MFASettings) SanitizedMFAVerifyBanner() string {
	return sanitizeThemeBannerSubpath(ms.VerifyBanner)
}

// SanitizedMFAEnrollBanner returns EnrollBanner as a safe theme-relative subpath, or empty if invalid.
func (ms MFASettings) SanitizedMFAEnrollBanner() string {
	return sanitizeThemeBannerSubpath(ms.EnrollBanner)
}

// MFAIssuer returns the TOTP issuer label for otpauth URLs and authenticator apps.
func (c *Config) MFAIssuer() string {
	iss := strings.TrimSpace(c.Settings.MFA.Issuer)
	if iss != "" {
		return iss
	}
	if n := strings.TrimSpace(c.Settings.General.Name); n != "" {
		return n
	}
	return "ISIS-CNC"
}

// MFARequiredForUser reports whether this SSH login must complete TOTP (enrollment or code prompt).
func (c *Config) MFARequiredForUser(u *User) bool {
	if c.Settings.MFA.ForceAllUsers {
		return true
	}
	return u.MFAEnabled
}

// MFACodePrompt returns the TOTP line prompt (no ANSI); default "Authenticator code: " when unset.
func (c *Config) MFACodePrompt() string {
	if c == nil {
		return "Authenticator code: "
	}
	p := c.Settings.MFA.CodePrompt
	if strings.TrimSpace(p) == "" {
		return "Authenticator code: "
	}
	return p
}

type GeneralSettings struct {
	LogIPs     bool   `json:"log_ips"`
	Name       string `json:"name"`
	AutoReload bool   `json:"auto_reload"`
}

// TitleSettings controls window title refresh and spinner animation.
// Title *content* comes from assets/banners/{theme}/branding/title.txt (TermFX).
// Spinner *frames* come from branding/spinner.txt (see assets/TermFX.md).
type TitleSettings struct {
	UpdateSleep    int `json:"title_update_sleep"`    // ms between title refreshes if spinner_frame_sleep is 0
	SpinnerFrameMs int `json:"spinner_frame_sleep"` // ms between spinner frames; 0 = use title_update_sleep
}

type InfoRewrites struct {
	IPAddress  string `json:"ip_address"`
	Username   string `json:"username"`
	UnknownSSH string `json:"unknown_sshclient"`
	// When true, admin and mod SSH users see real target host and username on ongoing/recent for everyone’s rows.
	// When false (default), they see the same ip_address/username rewrites as normal users for rows that are not theirs.
	StaffSeeAllOngoingDetails bool `json:"staff_see_all_ongoing_details"`
}

type DeveloperSettings struct {
	Terminal TerminalSettings `json:"terminal"`
}

type TerminalSettings struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type Webhooks struct {
	Telegram TelegramWebhook `json:"telegram"`
	Discord  DiscordWebhook  `json:"discord"`
}

type TelegramWebhook struct {
	Token   string `json:"token"`
	ChatID  string `json:"chatid"`
	Enabled bool   `json:"enabled"`
}

type DiscordWebhook struct {
	Webhook string `json:"webhook"`
	Image   string `json:"image"`
	Enabled bool   `json:"enabled"`
}

type AttackSettings struct {
	Blacklists        []string      `json:"blacklists"`
	Attacks           AttacksConfig `json:"attacks"`
	BlockPrivateHosts bool          `json:"block_private_hosts"`
}

type AttacksConfig struct {
	Enabled   bool        `json:"enabled"`
	Slots     SlotsConfig `json:"slots"`
	SpamCheck SpamCheck   `json:"spamcheck"`
}

type SlotsConfig struct {
	Max     int  `json:"max"`
	Enabled bool `json:"enabled"`
}

type SpamCheck struct {
	General SpamRule `json:"general"`
	Target  SpamRule `json:"target"`
}

type SpamRule struct {
	Amount     int  `json:"amount"`
	PerSeconds int  `json:"per_seconds"`
	Enabled    bool `json:"enabled"`
}

type Preset struct {
	Name   string       `json:"name"`
	Config PresetConfig `json:"config"`
}

type PresetConfig struct {
	MaxTime     int  `json:"maxtime"`
	Concurrents int  `json:"concurrents"`
	VIP         bool `json:"vip"`
	Expiry      int  `json:"expiry"`
}

type Theme struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Example     string `json:"example"`
	Colour      string `json:"colour"`
}

type BannerDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RequireRole RoleReq  `json:"require_role"`
	Path        string   `json:"path"`
	Aliases     []string `json:"aliases"`
}

type RoleReq struct {
	Admin    bool `json:"admin"`
	Mod      bool `json:"mod"`
	Reseller bool `json:"reseller"`
}

type MethodGroup struct {
	Name     string `json:"name"`
	MaxSlots int    `json:"max_slots"`
	MaxTime  int    `json:"max_time"`
}

type AttackDef struct {
	Method string          `json:"method"`
	Group  string          `json:"group"`
	Links  []string        `json:"links"`
	Config AttackDefConfig `json:"config"`
}

type AttackDefConfig struct {
	Slots   SlotsConfig   `json:"slots"`
	MaxTime MaxTimeConfig `json:"maxtime"`
	Status  StatusConfig  `json:"status"`
}

type MaxTimeConfig struct {
	Hard TimeLimit `json:"hard"`
	Soft TimeLimit `json:"soft"`
}

type TimeLimit struct {
	Time    int  `json:"time"`
	Enabled bool `json:"enabled"`
}

type StatusConfig struct {
	Enabled bool          `json:"enabled"`
	VIP     bool          `json:"vip"`
	Private PrivateConfig `json:"private"`
}

type PrivateConfig struct {
	Enabled bool     `json:"enabled"`
	Users   []string `json:"users"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.ServerConfig.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) FindAttack(method string) *AttackDef {
	for i := range c.Attacks {
		if c.Attacks[i].Method == method {
			return &c.Attacks[i]
		}
	}
	return nil
}

func (c *Config) FindPreset(name string) *Preset {
	for i := range c.Presets {
		if c.Presets[i].Name == name {
			return &c.Presets[i]
		}
	}
	return nil
}

func (c *Config) FindTheme(name string) *Theme {
	for i := range c.Themes {
		if c.Themes[i].Name == name {
			return &c.Themes[i]
		}
	}
	return nil
}

func (c *Config) FindMethodGroup(name string) *MethodGroup {
	for i := range c.MethodGroups {
		if c.MethodGroups[i].Name == name {
			return &c.MethodGroups[i]
		}
	}
	return nil
}

func (c *Config) GetGroupMethods(groupName string) []string {
	var methods []string
	for _, a := range c.Attacks {
		if a.Group == groupName {
			methods = append(methods, a.Method)
		}
	}
	return methods
}

func (c *Config) IsCommandDisabled(cmd string) bool {
	for _, d := range c.Settings.DisabledCommands {
		if d == cmd {
			return true
		}
	}
	return false
}
