package core

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// TermFX placeholders: <<$key>> with optional spaces, e.g. << $ user.username >>.
// Keys are alphanumerics, underscores, and dots (e.g. cfx.players.current).
var termfxPlaceholderRE = regexp.MustCompile(`<<\s*\$\s*([a-zA-Z0-9_.]+)\s*>>`)

// termfxTrailingClearRE: trailing <<$clear>> would erase the whole splash after render; strip at EOF only.
var termfxTrailingClearRE = regexp.MustCompile(`<<\s*\$\s*clear\s*>>\s*\z`)

// Bare title vars: $title.spinner (some editors/users omit << >>).
var bareTitlePlaceholderRE = regexp.MustCompile(`\$((?:title)\.[a-zA-Z0-9_]+)\b`)

// Curly title vars: {title.time} or {$title.time}
var curlyTitlePlaceholderRE = regexp.MustCompile(`\{\s*\$?\s*((?:title)\.[a-zA-Z0-9_]+)\s*\}`)

// ansiCSI strips SGR and most CSI sequences (e.g. from boolLabel) so window titles stay valid.
var ansiCSI = regexp.MustCompile("\x1b\\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]")

// resolveTermFXKey maps common typos and aliases to real context keys (pass lowercase input).
func resolveTermFXKey(key string) string {
	switch key {
	case "title.spiiner", "title.spiner", "title.spinnner", "title.spinnr", "title.spin":
		return "title.spinner"
	case "title.tim", "title.times", "title.clock":
		return "title.time"
	case "title.dt", "title.dateime":
		return "title.datetime"
	case "title.fb", "title.fakebot":
		return "title.fakebots"
	}
	return key
}

func termfxLookup(ctx map[string]string, key string) (string, bool) {
	k := resolveTermFXKey(strings.ToLower(key))
	if v, ok := ctx[k]; ok {
		return v, true
	}
	return "", false
}

func expandBareAndCurlyTitleVars(s string, ctx map[string]string) string {
	s = bareTitlePlaceholderRE.ReplaceAllStringFunc(s, func(full string) string {
		m := bareTitlePlaceholderRE.FindStringSubmatch(full)
		if len(m) < 2 {
			return full
		}
		if v, ok := termfxLookup(ctx, m[1]); ok {
			return v
		}
		return full
	})
	s = curlyTitlePlaceholderRE.ReplaceAllStringFunc(s, func(full string) string {
		m := curlyTitlePlaceholderRE.FindStringSubmatch(full)
		if len(m) < 2 {
			return full
		}
		if v, ok := termfxLookup(ctx, m[1]); ok {
			return v
		}
		return full
	})
	return s
}

func ReadBannerFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := decodeBannerText(data)
	s = normalizeTermFXBrackets(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n") // lone CR so tokens aren’t stuck to \r
	return s
}

func readBannerFileNearExecutable(rel string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		dir = filepath.Dir(exe)
	}
	rel = filepath.FromSlash(rel)
	for _, root := range []string{dir, filepath.Join(dir, ".."), filepath.Join(dir, "..", "..")} {
		full := filepath.Join(filepath.Clean(root), rel)
		if b, e := os.ReadFile(full); e == nil {
			return b, nil
		}
	}
	return nil, os.ErrNotExist
}

// decodeBannerText handles UTF-8 (with optional BOM) and UTF-16 LE/BE (Notepad “Unicode”).
func decodeBannerText(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		s := utf16BytesToString(data[2:], binary.LittleEndian)
		return strings.TrimPrefix(s, "\uFEFF")
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		s := utf16BytesToString(data[2:], binary.BigEndian)
		return strings.TrimPrefix(s, "\uFEFF")
	}
	s := string(data)
	s = strings.TrimPrefix(s, "\ufeff") // UTF-8 BOM
	return s
}

func utf16BytesToString(b []byte, order binary.ByteOrder) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return ""
	}
	n := len(b) / 2
	u := make([]uint16, n)
	for i := range u {
		u[i] = order.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// normalizeTermFXBrackets maps fullwidth / small angle brackets to ASCII so <<$…>> matches.
func normalizeTermFXBrackets(s string) string {
	return strings.NewReplacer(
		"\uFF1C", "<", // ＜
		"\uFF1E", ">", // ＞
		"\uFE64", "<", // ﹤
		"\uFE65", ">", // ﹥
	).Replace(s)
}

// ensureTermFXTitleKeys adds <<$title.*>> keys when missing (e.g. broadcast / attack-only maps).
// title.spinner / title.fakebots are title-bar-only — panels get empty strings here.
// BuildPreAuthBannerContext is for SSH BannerCallback before any user is authenticated (no user.* keys).
func BuildPreAuthBannerContext(cfg *Config) map[string]string {
	ctx := make(map[string]string)
	now := time.Now()
	ctx["date"] = now.Format("01/02/2006")
	ctx["datetime"] = now.Format("01/02/2006 15:04:05")
	ctx["time"] = now.Format("15:04:05")
	name := ""
	if cfg != nil {
		name = strings.TrimSpace(cfg.Settings.General.Name)
	}
	if name == "" {
		name = "ISIS-CNC"
	}
	ctx["general.name"] = name
	ensureTermFXTitleKeys(ctx)
	return ctx
}

func ensureTermFXTitleKeys(ctx map[string]string) {
	if ctx == nil {
		return
	}
	now := time.Now()
	set := func(k, v string) {
		if _, ok := ctx[k]; !ok {
			ctx[k] = v
		}
	}
	set("title.spinner", "")
	set("title.fakebots", "")
	set("title.time", now.Format("15:04:05"))
	set("title.datetime", now.Format("01/02/2006 15:04:05"))
	if d, ok := ctx["date"]; ok {
		set("title.date", d)
	} else {
		set("title.date", now.Format("01/02/2006"))
	}
}

func RenderTermFX(content string, ctx map[string]string) string {
	ensureTermFXTitleKeys(ctx)
	content = normalizeTermFXBrackets(content)
	content = strings.TrimRight(content, "\r\n")
	content = termfxTrailingClearRE.ReplaceAllString(content, "")
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	result := termfxPlaceholderRE.ReplaceAllStringFunc(content, func(full string) string {
		m := termfxPlaceholderRE.FindStringSubmatch(full)
		if len(m) < 2 {
			return full
		}
		lk := strings.ToLower(m[1])
		key := resolveTermFXKey(lk)
		switch key {
		case "clear":
			return "\033[2J\033[H"
		case "skipline":
			return "\r\n"
		}
		if v, ok := ctx[key]; ok {
			return v
		}
		return full
	})

	result = expandBareAndCurlyTitleVars(result, ctx)

	result = strings.ReplaceAll(result, "\n", "\r\n")
	result = strings.ReplaceAll(result, "\r\r\n", "\r\n")

	return result
}

func BuildUserContext(user *User, server *Server, db *Database) map[string]string {
	ctx := make(map[string]string)

	ctx["user.username"] = user.Username
	ctx["user.maxtime"] = strconv.Itoa(user.MaxTime)
	ctx["user.concurrents"] = strconv.Itoa(user.Concurrents)
	ctx["user.vip"] = boolLabel(user.VIP)
	ctx["user.reseller"] = boolLabel(user.Reseller)
	ctx["user.mod"] = boolLabel(user.Mod)
	ctx["user.admin"] = boolLabel(user.Admin)
	ctx["user.bp_powersaving"] = boolLabel(user.BypassPowersaving)
	ctx["user.bp_blacklist"] = boolLabel(user.BypassBlacklist)
	ctx["user.bp_softmaxtime"] = boolLabel(user.BypassSoftMaxtime)
	ctx["user.api"] = boolLabel(user.APIAccess)

	ongoingCount, _ := db.GetUserOngoingCount(user.Username)
	ctx["user.ongoing"] = strconv.Itoa(ongoingCount)

	attackCount, _ := db.GetUserAttackCount(user.Username)
	ctx["user.attackcount"] = strconv.Itoa(attackCount)

	now := time.Now().Unix()
	daysCreated := (now - user.TimeCreated) / 86400
	ctx["user.creation.days"] = strconv.FormatInt(daysCreated, 10)

	if user.Expire == 0 {
		ctx["user.expiry.days"] = "Never"
		ctx["user.expiry.formatted"] = "No expiry"
	} else {
		daysExpiry := (user.Expire - now) / 86400
		ctx["user.expiry.days"] = strconv.FormatInt(daysExpiry, 10)
		if user.Expire < now {
			ctx["user.expiry.formatted"] = "Expired"
		} else {
			ctx["user.expiry.formatted"] = time.Unix(user.Expire, 0).Format("Jan 02, 2006")
		}
	}
	ctx["user.creation.formatted"] = time.Unix(user.TimeCreated, 0).Format("Jan 02, 2006")
	ctx["user.creation.user"] = user.CreatedBy

	online := "0"
	if server != nil {
		online = strconv.Itoa(server.GetOnlineCount())
	}
	ctx["general.online"] = online
	ctx["online"] = online

	globalOngoing, _ := db.GetOngoingCount()
	ctx["general.ongoing"] = strconv.Itoa(globalOngoing)
	ctx["ongoing"] = strconv.Itoa(globalOngoing)

	totalAttacks, _ := db.GetUserAttackCount(user.Username)
	ctx["general.attackcount"] = strconv.Itoa(totalAttacks)

	wall := time.Now()
	ctx["date"] = wall.Format("01/02/2006")
	ctx["datetime"] = wall.Format("01/02/2006 15:04:05")
	ctx["time"] = wall.Format("15:04:05")

	// Same tokens as the window title (title.txt) so <<$title.spinner>> etc. work in *all* banners.
	ctx["title.time"] = ctx["time"]
	ctx["title.datetime"] = ctx["datetime"]
	ctx["title.date"] = ctx["date"]
	// title.spinner / title.fakebots are only set for the window title (BuildTitleContext).

	name := ""
	if server != nil {
		if cfg := server.GetConfig(); cfg != nil {
			name = strings.TrimSpace(cfg.Settings.General.Name)
		}
	}
	if name == "" {
		name = "ISIS-CNC"
	}
	ctx["general.name"] = name

	return ctx
}

// DefaultSpinnerFrames is used when branding/spinner.txt is missing or invalid.
func DefaultSpinnerFrames() []string {
	return []string{"|", "/", "-", "+"}
}

// ParseSpinnerFrames parses branding/spinner.txt body:
//   - If two or more non-empty, non-comment lines: each line is one frame (spaces allowed).
//   - If exactly one such line: split on whitespace (e.g. "I IS ISI ISIS").
// Lines starting with # are ignored. Inline " #" starts a comment on that line.
func ParseSpinnerFrames(content string) []string {
	content = strings.TrimSpace(content)
	if content == "" {
		return DefaultSpinnerFrames()
	}
	var lines []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) >= 2 {
		return lines
	}
	if len(lines) == 1 {
		parts := strings.Fields(lines[0])
		if len(parts) == 0 {
			return DefaultSpinnerFrames()
		}
		return parts
	}
	return DefaultSpinnerFrames()
}

// SanitizeTitleSpinnerFrame removes bytes that break OSC 0 window titles.
func SanitizeTitleSpinnerFrame(s string) string {
	s = strings.ReplaceAll(s, "\033", "")
	s = strings.ReplaceAll(s, "\007", "")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// BuildTitleContext merges panel context with title-bar-only placeholders (from branding/title.txt).
// spinner: one animation frame, e.g. | / - +
// fakeBots: random display value if you use <<$title.fakebots>> in title.txt
func BuildTitleContext(user *User, server *Server, db *Database, spinner string, fakeBots int) map[string]string {
	ctx := BuildUserContext(user, server, db)
	now := time.Now()
	ctx["title.spinner"] = spinner
	ctx["title.fakebots"] = strconv.Itoa(fakeBots)
	ctx["title.time"] = now.Format("15:04:05")
	ctx["title.datetime"] = now.Format("01/02/2006 15:04:05")
	ctx["title.date"] = ctx["date"]
	return ctx
}

// CollapseRenderedTitle turns banner output into a single line safe for the terminal window title (OSC 0).
func CollapseRenderedTitle(s string) string {
	s = ansiCSI.ReplaceAllString(s, "")
	// Strip any stray escape introducer so OSC 0 payload cannot be broken by usernames/colors.
	s = strings.ReplaceAll(s, "\033", "")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\007", "")
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

func BuildAttackContext(user *User, host, method string, port, duration int) map[string]string {
	ctx := make(map[string]string)
	ctx["target.host"] = host
	ctx["target.port"] = strconv.Itoa(port)
	ctx["target.duration"] = strconv.Itoa(duration)
	ctx["target.method"] = method
	ctx["target.timesent"] = time.Now().Format("15:04:05")
	ctx["user.username"] = user.Username
	ctx["user.concurrents"] = strconv.Itoa(user.Concurrents)
	ctx["user.maxtime"] = strconv.Itoa(user.MaxTime)
	ongoingStr := fmt.Sprintf("%d", 1)
	ctx["user.ongoing"] = ongoingStr
	return ctx
}

func BuildBroadcastContext(sender, message string) map[string]string {
	return map[string]string{
		"broadcast.sender":  sender,
		"broadcast.message": message,
	}
}

func boolLabel(b bool) string {
	if b {
		return "\033[97mTrue\033[97m"
	}
	return "\033[97mFalse\033[97m"
}
