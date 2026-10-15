package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func HandleCommand(s *Session, input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	if s.usersCmdResizeActive && cmd != "users" {
		s.resizeTerminalCSI(24, 80)
		s.usersCmdResizeActive = false
	}

	if s.config.IsCommandDisabled(cmd) {
		banner := s.RenderBanner("branding/command-1020.txt", nil)
		s.WriteRenderedTermFX(banner, 0, true)
		return
	}

	if HandleAdminCommand(s, cmd, args) {
		return
	}

	for _, b := range s.config.Banners {
		if b.Name == cmd || containsAlias(b.Aliases, cmd) {
			if !checkBannerPermission(s, b) {
				banner := s.RenderBanner("branding/command-403.txt", nil)
				s.WriteRenderedTermFX(banner, 0, true)
				return
			}
			banner := s.RenderBannerPath(b.Path, nil)
			s.WriteRenderedTermFX(banner, 0, false)
			return
		}
	}

	switch cmd {
	case "clear", "cls":
		cmdClear(s)
	case "passwd", "password":
		cmdPasswd(s, args)
	case "lookup":
		cmdLookup(s, args)
	case "cfx":
		cmdCFX(s, args)
	case "ping":
		cmdPing(s, args)
	case "paping":
		cmdPaping(s, args)
	case "ongoing":
		cmdOngoing(s)
	case "recent":
		cmdRecent(s)
	case "themes", "theme":
		cmdThemes(s, args)
	case "presets":
		cmdPresets(s, args)
	default:
		method := strings.ToUpper(cmd)
		attackDef := s.config.FindAttack(method)
		if attackDef != nil {
			cmdAttack(s, method, args)
		} else {
			s.Writeln("[97mUnknown command. Type 'help' for available commands.\033[97m")
		}
	}
}

func containsAlias(aliases []string, cmd string) bool {
	for _, a := range aliases {
		if strings.ToLower(a) == cmd {
			return true
		}
	}
	return false
}

func tableDisplayHost(s *Session, host string) string {
	r := strings.TrimSpace(s.config.Settings.InfoRewrites.IPAddress)
	if r != "" {
		return r
	}
	return host
}

func tableDisplayUsername(s *Session, username string) string {
	r := strings.TrimSpace(s.config.Settings.InfoRewrites.Username)
	if r != "" {
		return r
	}
	return username
}

// ongoingOrRecentDisplayHost shows the real host for your own rows; otherwise rewrites unless admin/mod with staff_see_all_ongoing_details.
func ongoingOrRecentDisplayHost(s *Session, rowOwner, host string) string {
	if strings.EqualFold(rowOwner, s.user.Username) {
		return host
	}
	if (s.user.Admin || s.user.Mod) && s.config.Settings.InfoRewrites.StaffSeeAllOngoingDetails {
		return host
	}
	return tableDisplayHost(s, host)
}

func ongoingOrRecentDisplayUser(s *Session, rowOwner, username string) string {
	if strings.EqualFold(rowOwner, s.user.Username) {
		return username
	}
	if (s.user.Admin || s.user.Mod) && s.config.Settings.InfoRewrites.StaffSeeAllOngoingDetails {
		return username
	}
	return tableDisplayUsername(s, username)
}

func checkBannerPermission(s *Session, b BannerDef) bool {
	if b.RequireRole.Admin && !s.user.Admin {
		return false
	}
	if b.RequireRole.Mod && !s.user.Mod && !s.user.Admin {
		return false
	}
	if b.RequireRole.Reseller && !s.user.Reseller && !s.user.Admin {
		return false
	}
	return true
}

func cmdClear(s *Session) {
	banner := s.RenderBanner("branding/clear-splash.txt", nil)
	if strings.TrimSpace(banner) == "" {
		s.ClearScreen()
		s.Writeln("\033[97m[Clear splash missing or empty: assets/banners/{theme}/branding/clear-splash.txt]\033[0m")
		return
	}
	banner = stripLeadingRIS(banner)
	s.WriteRenderedTermFX(banner, 0, false)
}

func cmdPasswd(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("\033[97mUsage: passwd <new_password>\033[0;97m")
		return
	}
	newPass := args[0]
	hash := sha256.Sum256([]byte(newPass))
	hashStr := hex.EncodeToString(hash[:])

	if err := s.db.UpdatePassword(s.user.Username, hashStr); err != nil {
		s.Writeln("\033[97mFailed to update password.\033[0;97m")
		return
	}
	s.user.Password = hashStr
	s.user.MustChangePassword = false
	s.Writeln("\033[97mPassword updated.\033[0;97m")
}

func cmdLookup(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: lookup <ip>\033[97m")
		return
	}
	ip := args[0]

	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		s.Writeln("[97mFailed to lookup IP.\033[97m")
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.Writeln("[97mFailed to parse lookup response.\033[97m")
		return
	}

	getString := func(key string) string {
		if v, ok := result[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return "N/A"
	}

	ctx := map[string]string{
		"ip.ip":        getString("query"),
		"ip.region":    getString("regionName"),
		"ip.country":   getString("country"),
		"ip.continent": getString("continent"),
		"ip.city":      getString("city"),
		"ip.zip":       getString("zip"),
		"ip.isp":       getString("isp"),
		"ip.asn":       getString("as"),
		"ip.org":       getString("org"),
		"ip.timezone":  getString("timezone"),
	}

	banner := s.RenderBanner("branding/iplookup.txt", ctx)
	if banner == "" {
		h := []string{"Field", "Value"}
		rows := [][]string{
			{"IP", getString("query")},
			{"Region", getString("regionName")},
			{"Country", getString("country")},
			{"Continent", getString("continent")},
			{"City", getString("city")},
			{"ZIP", getString("zip")},
			{"ISP", getString("isp")},
			{"ASN", getString("as")},
			{"Org", getString("org")},
			{"Timezone", getString("timezone")},
		}
		s.writeSimpleTable(h, rows)
	} else {
		s.WriteRenderedTermFX(banner, 0, false)
	}
}

func cmdCFX(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: cfx <code>\033[97m")
		return
	}
	code := args[0]

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://servers-frontend.fivem.net/api/servers/single/"+code, nil)
	if err != nil {
		s.Writeln("[97mFailed to create request.\033[97m")
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		s.Writeln("[97mFailed to resolve CFX code.\033[97m")
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.Writeln("[97mFailed to parse response.\033[97m")
		return
	}

	data, ok := result["Data"].(map[string]interface{})
	if !ok {
		s.Writeln("[97mServer not found or invalid response.\033[97m")
		return
	}

	serverIP := "N/A"
	serverPort := "N/A"
	if endpoints, ok := data["connectEndPoints"].([]interface{}); ok && len(endpoints) > 0 {
		endpoint := fmt.Sprintf("%v", endpoints[0])
		parts := strings.SplitN(endpoint, ":", 2)
		serverIP = parts[0]
		if len(parts) > 1 {
			serverPort = parts[1]
		}
	}

	playersNow := "0"
	playersMax := "0"
	if v, ok := data["clients"]; ok {
		playersNow = fmt.Sprintf("%v", v)
	}
	if v, ok := data["sv_maxclients"]; ok {
		playersMax = fmt.Sprintf("%v", v)
	}

	ipCtx := getCFXIPInfo(serverIP)

	ctx := map[string]string{
		"cfx.ip":              serverIP,
		"cfx.port":            serverPort,
		"cfx.code":            code,
		"cfx.country":         ipCtx["country"],
		"cfx.hosting":         ipCtx["isp"],
		"cfx.org":             ipCtx["org"],
		"cfx.players.current": playersNow,
		"cfx.players.max":     playersMax,
	}

	banner := s.RenderBanner("branding/fivem-resolve.txt", ctx)
	if banner == "" {
		h := []string{"Field", "Value"}
		rows := [][]string{
			{"IP", serverIP},
			{"Port", serverPort},
			{"CFX code", code},
			{"Country", ipCtx["country"]},
			{"Hosting (ISP)", ipCtx["isp"]},
			{"Org", ipCtx["org"]},
			{"Players", playersNow + " / " + playersMax},
		}
		s.writeSimpleTable(h, rows)
	} else {
		s.WriteRenderedTermFX(banner, 0, false)
	}
}

func getCFXIPInfo(ip string) map[string]string {
	defaults := map[string]string{
		"country": "N/A",
		"isp":     "N/A",
		"org":     "N/A",
	}

	if ip == "N/A" || ip == "" {
		return defaults
	}

	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return defaults
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return defaults
	}

	for _, key := range []string{"country", "isp", "org"} {
		if v, ok := result[key]; ok {
			defaults[key] = fmt.Sprintf("%v", v)
		}
	}
	return defaults
}

func cmdPing(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: ping <host_or_ip>\033[0;97m")
		return
	}
	target := args[0]
	s.Writeln(tTableWhite + "check-host.net ICMP check (ping)…" + tReset)
	rid, err := checkHostStartCheck("ping", target)
	if err != nil {
		s.Writeln(tTableWhite + err.Error() + tReset)
		return
	}
	raw, err := checkHostPollResult(rid, 45*time.Second)
	if err != nil {
		s.Writeln(tTableWhite + err.Error() + tReset)
		return
	}
	rows := checkHostResultRows(raw)
	if len(rows) == 0 {
		s.Writeln(tTableWhite + "(no result data)" + tReset)
		return
	}
	s.writeSimpleTable([]string{"Node", "Result"}, rows)
}

func cmdPaping(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: paping <ip> <port>\033[0;97m")
		return
	}
	host := strings.TrimSpace(args[0])
	port := strings.TrimSpace(args[1])
	tcpHost := host + ":" + port

	s.Writeln(tTableWhite + "check-host.net TCP check… " + tcpHost + tReset)
	rid, err := checkHostStartCheck("tcp", tcpHost)
	if err != nil {
		s.Writeln(tTableWhite + err.Error() + tReset)
		return
	}
	raw, err := checkHostPollResult(rid, 45*time.Second)
	if err != nil {
		s.Writeln(tTableWhite + err.Error() + tReset)
		return
	}
	rows := checkHostResultRows(raw)
	if len(rows) == 0 {
		s.Writeln(tTableWhite + "(no result data)" + tReset)
		return
	}
	s.writeSimpleTable([]string{"Node", "Result"}, rows)
}

func cmdOngoing(s *Session) {
	attacks, err := s.db.GetOngoingAttacks()
	if err != nil || len(attacks) == 0 {
		banner := s.RenderBanner("branding/no-ongoing.txt", nil)
		s.WriteRenderedTermFX(banner, 0, true)
		return
	}

	headers := []string{"#", "Target", "Method", "Port", "Length", "Finish", "User"}
	now := time.Now().Unix()
	var rows [][]string
	for i, atk := range attacks {
		remaining := (atk.TimeSent + int64(atk.Duration)) - now
		if remaining < 0 {
			remaining = 0
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			ongoingOrRecentDisplayHost(s, atk.Username, atk.Host),
			atk.Method,
			fmt.Sprintf("%d", atk.Port),
			fmt.Sprintf("%d", atk.Duration),
			fmt.Sprintf("%d secs", remaining),
			ongoingOrRecentDisplayUser(s, atk.Username, atk.Username),
		})
	}

	s.writeSimpleTable(headers, rows)
}

func cmdRecent(s *Session) {
	attacks, err := s.db.GetRecentAttacks(s.user.Username, 10)
	if err != nil || len(attacks) == 0 {
		banner := s.RenderBanner("branding/no-recent.txt", nil)
		s.WriteRenderedTermFX(banner, 0, true)
		return
	}

	headers := []string{"#", "Target", "Method", "Port", "Length", "Sent", "User"}
	var rows [][]string
	for i, atk := range attacks {
		sentTime := time.Unix(atk.TimeSent, 0).Format("01/02 15:04")
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			ongoingOrRecentDisplayHost(s, atk.Username, atk.Host),
			atk.Method,
			fmt.Sprintf("%d", atk.Port),
			fmt.Sprintf("%d", atk.Duration),
			sentTime,
			ongoingOrRecentDisplayUser(s, atk.Username, atk.Username),
		})
	}

	s.writeSimpleTable(headers, rows)
}

func cmdPresets(s *Session, args []string) {
	if !s.user.Admin {
		banner := s.RenderBanner("branding/command-403.txt", nil)
		s.WriteRenderedTermFX(banner, 0, true)
		return
	}
	if len(args) < 1 {
		s.Writeln("[97mUsage: presets list | presets use <PRESET_NAME>\033[97m")
		s.Writeln("[97mPresets: " + listPresets(s.config) + "\033[97m")
		return
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	switch sub {
	case "list", "ls":
		cmdPresetsList(s)
	case "use":
		if len(args) < 2 {
			s.Writeln("[97mUsage: presets use <PRESET_NAME>\033[97m")
			s.Writeln("[97mPresets: " + listPresets(s.config) + "\033[97m")
			return
		}
		presetName := strings.ToUpper(strings.TrimSpace(args[1]))
		if s.config.FindPreset(presetName) == nil {
			s.Writeln("[97mUnknown preset. Available: " + listPresets(s.config) + "\033[97m")
			return
		}
		s.Write("[0;97mUsername: \033[0m")
		unameRaw, err := s.ReadLine()
		if err != nil {
			return
		}
		s.Write("[0;97mPassword: \033[0m")
		pass, err := s.ReadPassword()
		if err != nil {
			return
		}
		u, preset, th, err := tryCreateUserWithPreset(s, unameRaw, pass, presetName, "default")
		if err != nil {
			s.Writeln("[97m" + err.Error() + "\033[97m")
			return
		}
		s.Writeln(fmt.Sprintf("[97mCreated '%s' preset=%s theme=%s\033[97m", u, preset, th))
	default:
		s.Writeln("[97mUsage: presets list | presets use <PRESET_NAME>\033[97m")
		s.Writeln("[97mPresets: " + listPresets(s.config) + "\033[97m")
	}
}

func cmdPresetsList(s *Session) {
	if len(s.config.Presets) == 0 {
		s.Writeln("[97mNo presets in config.\033[97m")
		return
	}
	headers := []string{"Preset", "MaxT", "C", "VIP", "Expiry (d)"}
	var rows [][]string
	for _, p := range s.config.Presets {
		vip := "no"
		if p.Config.VIP {
			vip = "yes"
		}
		rows = append(rows, []string{
			p.Name,
			fmt.Sprintf("%d", p.Config.MaxTime),
			fmt.Sprintf("%d", p.Config.Concurrents),
			vip,
			fmt.Sprintf("%d", p.Config.Expiry),
		})
	}
	s.writeSimpleTable(headers, rows)
}

func cmdThemes(s *Session, args []string) {
	if len(args) == 0 {
		headers := []string{"Name", "Description"}
		var rows [][]string
		for _, th := range s.config.Themes {
			name := "  " + th.Name
			if th.Name == s.user.Theme {
				name = "* " + th.Name
			}
			rows = append(rows, []string{name, th.Description})
		}
		s.writeSimpleTable(headers, rows)
		s.Writeln(tTableWhite + "Usage: themes <name>" + tReset)
		return
	}

	themeName := strings.ToLower(args[0])
	theme := s.config.FindTheme(themeName)
	if theme == nil {
		s.Writeln("[97mTheme not found.\033[97m")
		return
	}

	if err := s.db.SetTheme(s.user.Username, themeName); err != nil {
		s.Writeln("[97mFailed to update theme.\033[97m")
		return
	}
	s.user.Theme = themeName
	s.Writeln(fmt.Sprintf("[97mTheme changed to '%s'.\033[97m", themeName))
}

func cmdAttack(s *Session, method string, args []string) {
	if len(args) < 3 {
		s.Writeln(fmt.Sprintf("[97mUsage: %s <host> <port> <duration>\033[97m", strings.ToLower(method)))
		s.Writeln("[97mHost: IPv4/IPv6, or http(s)://hostname (hostname must include a dot unless it is an IP).\033[97m")
		return
	}

	host := strings.TrimSpace(args[0])
	port, err := strconv.Atoi(args[1])
	if err != nil || port < 1 || port > 65535 {
		s.Writeln("[97mInvalid port number.\033[97m")
		return
	}
	duration, err := strconv.Atoi(args[2])
	if err != nil || duration < 1 {
		s.Writeln("[97mInvalid duration.\033[97m")
		return
	}

	if err := s.attacks.SendAttack(s, method, host, port, duration); err != nil {
		s.WriteRenderedTermFX(tTableWhite+FormatAttackUserError(s, err)+tReset, 0, true)
		return
	}

	ctx := BuildAttackContext(s.user, host, method, port, duration)
	banner := s.RenderBanner("branding/attack-sent.txt", ctx)
	s.WriteRenderedTermFX(banner, 0, false)
	if !strings.HasSuffix(banner, "\n") {
		s.Writeln("")
	}
}
