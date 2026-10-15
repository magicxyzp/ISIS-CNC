package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func HandleAdminCommand(s *Session, cmd string, args []string) bool {
	switch cmd {
	case "users":
		HandleUsersCommand(s, args)
		return true
	case "broadcast", "bc":
		requireAdmin(s, func() { adminBroadcast(s, args) })
		return true
	case "reload":
		requireAdmin(s, func() { adminReloadConfig(s) })
		return true
	}
	return false
}

func adminReloadConfig(s *Session) {
	if s.server == nil {
		s.Writeln("[97mReload is not available in this session.\033[97m")
		return
	}
	if err := s.server.ReloadConfig(); err != nil {
		s.Writeln(fmt.Sprintf("[97mConfig reload failed: %s\033[97m", err.Error()))
		return
	}
	s.Writeln("[97mConfig reloaded from disk. (SSH/API listen addresses and DB settings still require a full restart.)\033[97m")
}

func HandleUsersCommand(s *Session, args []string) {
	if !s.user.Mod && !s.user.Admin {
		s.Writeln("[97mYou do not have permission to use user management.\033[97m")
		return
	}
	// 112x29 for users admin UI; HandleCommand restores 80x24 on non-users commands.
	s.resizeTerminalCSI(29, 112)
	s.usersCmdResizeActive = true
	if len(args) < 1 {
		usersHelp(s)
		return
	}
	sub := strings.ToLower(args[0])
	rest := args[1:]

	modOnly := map[string]bool{"ban": true, "unban": true, "lock": true, "unlock": true}
	if modOnly[sub] {
		if !s.user.Mod && !s.user.Admin {
			s.Writeln("[97mYou do not have permission to use this command.\033[97m")
			return
		}
	} else {
		if !s.user.Admin {
			s.Writeln("[97mYou do not have permission to use this command.\033[97m")
			return
		}
	}

	switch sub {
	case "help", "?":
		usersHelp(s)
	case "add", "create":
		usersAdd(s, rest)
	case "remove", "delete":
		usersRemove(s, rest)
	case "list":
		usersList(s)
	case "info", "whois":
		usersInfo(s, rest)
	case "rename":
		usersRename(s, rest)
	case "ban":
		usersBan(s, rest)
	case "unban":
		usersUnban(s, rest)
	case "lock":
		usersLock(s, rest)
	case "unlock":
		usersUnlock(s, rest)
	case "extend":
		usersExtend(s, rest)
	case "extendall":
		usersExtendAll(s, rest)
	case "setmaxtime":
		usersSetMaxTime(s, rest)
	case "setconc":
		usersSetConc(s, rest)
	case "setexpiry":
		usersSetExpiry(s, rest)
	case "settheme":
		usersSetTheme(s, rest)
	case "resetpw":
		usersResetPW(s, rest)
	case "setadmin":
		usersSetRole(s, rest, "admin")
	case "setmod":
		usersSetRole(s, rest, "mod")
	case "setreseller":
		usersSetRole(s, rest, "reseller")
	case "setvip":
		usersSetRole(s, rest, "vip")
	case "bypass":
		usersBypass(s, rest)
	case "api":
		usersSetAPI(s, rest)
	case "mfa":
		usersMFA(s, rest)
	default:
		s.Writeln("[97mUnknown users subcommand. Try: users help\033[97m")
	}
}

func usersHelp(s *Session) {
	headers := []string{"Command", "Description"}
	if !s.user.Admin {
		rows := [][]string{
			{"users ban <u>", "Ban account"},
			{"users unban <u>", "Remove ban"},
			{"users lock <u>", "Lock account"},
			{"users unlock <u>", "Unlock account"},
		}
		s.writeSimpleTable(headers, rows)
		return
	}
	rows := [][]string{
		{"users help | ?", "This menu"},
		{"users list", "All accounts"},
		{"users info <u>", "Full profile"},
		{"users add", "Wizard (plan + bypass); or add <u> <pw> <preset> [theme]"},
		{"users remove <u>", "Delete user"},
		{"users rename <o> <n>", "Rename login"},
		{"users ban | unban <u>", "Ban / unban (mod+)"},
		{"users lock | unlock <u>", "Lock / unlock (mod+)"},
		{"users extend <u> <days>", "Add days to plan end"},
		{"users extendall <days>", "Extend every finite plan"},
		{"users setmaxtime <u> <sec>", "Max attack seconds"},
		{"users setconc <u> <n>", "Concurrent attacks"},
		{"users setexpiry <u> <d>", "0=lifetime, else days from now"},
		{"users settheme <u> <t>", "UI theme"},
		{"users resetpw <u> <pw>", "New password"},
		{"users setadmin | setmod | setvip | setreseller <u>", "Toggle role"},
		{"users bypass <u> <bl|soft|ps|all> <on|off>", "Bypass flags"},
		{"users api <u> <on|off>", "HTTP /api/attack access"},
		{"users mfa <u> <on|off|reset>", "TOTP (Google Authenticator)"},
		{"broadcast <msg> | bc <msg>", "Message all online users (admin)"},
		{"reload", "Reload config from disk (admin)"},
	}
	s.writeSimpleTable(headers, rows)
}

func requireAdmin(s *Session, fn func()) {
	if !s.user.Admin {
		banner := s.RenderBanner("branding/command-403.txt", nil)
		s.WriteRenderedTermFX(banner, 0, true)
		return
	}
	fn()
}

func writeDBErr(s *Session, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, ErrUserNotFound) {
		s.Writeln("[97mUser not found.\033[97m")
		return
	}
	s.Writeln(fmt.Sprintf("[97m%s\033[97m", err.Error()))
}

func guardLastAdmin(s *Session, target string) bool {
	tu, err := s.db.GetUser(target)
	if err != nil {
		return true
	}
	if !tu.Admin {
		return true
	}
	n, err := s.db.CountAdmins()
	if err != nil {
		s.Writeln("[97mFailed to verify admin count.\033[97m")
		return false
	}
	if n <= 1 {
		s.Writeln("[97mCannot modify the only administrator account.\033[97m")
		return false
	}
	return true
}

func parseOnOff(arg string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "1", "true", "yes", "enable", "enabled":
		return true, true
	case "off", "0", "false", "no", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

// tryCreateUserWithPreset validates input and inserts the user. presetName is uppercased; theme "" means default.
func tryCreateUserWithPreset(s *Session, username, password, presetName, theme string) (unameOut string, presetOut string, themeOut string, err error) {
	presetName = strings.ToUpper(strings.TrimSpace(presetName))
	if theme == "" {
		theme = "default"
	}
	theme = strings.ToLower(theme)
	unameOut, err = ValidateUsername(username)
	if err != nil {
		return "", "", "", err
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return "", "", "", fmt.Errorf("password cannot be empty")
	}
	_, err = s.db.GetUser(unameOut)
	if err == nil {
		return "", "", "", fmt.Errorf("user already exists")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", "", fmt.Errorf("database error")
	}
	preset := s.config.FindPreset(presetName)
	if preset == nil {
		return "", "", "", fmt.Errorf("preset not found (available: %s)", listPresets(s.config))
	}
	if s.config.FindTheme(theme) == nil {
		return "", "", "", fmt.Errorf("theme not found")
	}
	hash := sha256.Sum256([]byte(password))
	hashStr := hex.EncodeToString(hash[:])
	if err := s.db.CreateUser(unameOut, hashStr, s.user.Username, theme,
		preset.Config.MaxTime, preset.Config.Concurrents, preset.Config.VIP, preset.Config.Expiry,
		false, false, false, false); err != nil {
		return "", "", "", err
	}
	adminLog(s, "users_add", fmt.Sprintf("target=%s", unameOut))
	return unameOut, presetName, theme, nil
}

func usersAdd(s *Session, args []string) {
	if len(args) == 0 {
		usersAddInteractive(s)
		return
	}
	if len(args) < 3 {
		s.Writeln("[97mUsage: users add  (wizard: username, password, plan, bypasses)\033[97m")
		s.Writeln("[97m   or: users add <username> <password> <preset> [theme]\033[97m")
		s.Writeln("[97mPresets: " + listPresets(s.config) + "  -  presets use <name> for short flow\033[97m")
		return
	}
	theme := "default"
	if len(args) >= 4 {
		theme = strings.ToLower(args[3])
	}
	u, preset, th, err := tryCreateUserWithPreset(s, args[0], args[1], args[2], theme)
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	s.Writeln(fmt.Sprintf("[97mCreated '%s' preset=%s theme=%s\033[97m", u, preset, th))
}

func readPromptLine(s *Session, prompt string) string {
	s.Write(tTableWhite + prompt + tReset)
	v, err := s.ReadLine()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func readPromptPassword(s *Session, prompt string) string {
	s.Write(tTableWhite + prompt + tReset)
	v, err := s.ReadPassword()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// parseOnOffLineOrNo: empty line means false; otherwise parseOnOff (yes/on/etc).
func parseOnOffLineOrNo(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return false
	}
	on, ok := parseOnOff(line)
	if !ok {
		return false
	}
	return on
}

// parseOnOffLineOrDefault uses def when line is empty; otherwise parseOnOff.
func parseOnOffLineOrDefault(line string, def bool) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return def
	}
	on, ok := parseOnOff(line)
	if !ok {
		return def
	}
	return on
}

func usersAddInteractive(s *Session) {
	s.Writeln("")
	s.Writeln(tTableWhite + "Create user - leave bypass/API lines empty for no (off)." + tReset)
	s.Writeln("")

	defMax, defConc, defExp := 300, 1, 30
	defVIP := false
	preIn := readPromptLine(s, "Optional preset to pre-fill plan (empty skip): ")
	if preIn != "" {
		if p := s.config.FindPreset(strings.ToUpper(preIn)); p != nil {
			defMax = p.Config.MaxTime
			defConc = p.Config.Concurrents
			defVIP = p.Config.VIP
			defExp = p.Config.Expiry
			s.Writeln(tTableWhite + "Using preset defaults for plan fields (you can override each prompt)." + tReset)
		} else {
			s.Writeln(tTableWhite + "Unknown preset - using generic defaults in brackets." + tReset)
		}
	}
	s.Writeln("")

	var uname string
	for {
		u := readPromptLine(s, "Username: ")
		if u == "" {
			s.Writeln(tTableWhite + "Cancelled." + tReset)
			return
		}
		var err error
		uname, err = ValidateUsername(u)
		if err != nil {
			s.Writeln(tTableWhite + err.Error() + tReset)
			continue
		}
		break
	}

	_, err := s.db.GetUser(uname)
	if err == nil {
		s.Writeln(tTableWhite + "User already exists." + tReset)
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		s.Writeln(tTableWhite + "Database error." + tReset)
		return
	}

	pass := readPromptPassword(s, "Password: ")
	if pass == "" {
		s.Writeln(tTableWhite + "Password cannot be empty." + tReset)
		return
	}

	maxT := defMax
	if v := readPromptLine(s, fmt.Sprintf("Max attack time (seconds) [%d]: ", defMax)); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			maxT = n
		} else {
			s.Writeln(tTableWhite + "Invalid - using default." + tReset)
		}
	}

	conc := defConc
	if v := readPromptLine(s, fmt.Sprintf("Concurrent attacks [%d]: ", defConc)); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			conc = n
		} else {
			s.Writeln(tTableWhite + "Invalid - using default." + tReset)
		}
	}

	expDays := defExp
	if v := readPromptLine(s, fmt.Sprintf("Plan length in days (0 = lifetime) [%d]: ", defExp)); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= 0 {
			expDays = n
		} else {
			s.Writeln(tTableWhite + "Invalid - using default." + tReset)
		}
	}

	vip := parseOnOffLineOrDefault(readPromptLine(s, fmt.Sprintf("VIP? yes/no (empty = default %s): ", map[bool]string{true: "yes", false: "no"}[defVIP])), defVIP)

	theme := "default"
	if v := readPromptLine(s, "Theme name [default]: "); v != "" {
		theme = strings.ToLower(v)
	}
	if s.config.FindTheme(theme) == nil {
		s.Writeln(tTableWhite + "Theme not found - using default." + tReset)
		theme = "default"
	}

	s.Writeln("")
	s.Writeln(tTableWhite + "Bypass / API (empty = no):" + tReset)
	bpBL := parseOnOffLineOrNo(readPromptLine(s, "Bypass blacklist? yes/no: "))
	bpSoft := parseOnOffLineOrNo(readPromptLine(s, "Bypass soft max time? yes/no: "))
	bpPS := parseOnOffLineOrNo(readPromptLine(s, "Bypass powersaving? yes/no: "))
	apiOn := parseOnOffLineOrNo(readPromptLine(s, "API access? yes/no: "))

	hash := sha256.Sum256([]byte(pass))
	hashStr := hex.EncodeToString(hash[:])
	if err := s.db.CreateUser(uname, hashStr, s.user.Username, theme, maxT, conc, vip, expDays, bpPS, bpBL, bpSoft, apiOn); err != nil {
		s.Writeln(tTableWhite + "Failed: " + err.Error() + tReset)
		return
	}
	adminLog(s, "users_add", fmt.Sprintf("target=%s interactive", uname))
	s.Writeln("")
	s.Writeln(tTableWhite + fmt.Sprintf("Created '%s'  maxT=%d conc=%d vip=%v expiry_days=%d theme=%s  bypass bl/soft/ps=%v/%v/%v api=%v",
		uname, maxT, conc, vip, expDays, theme, bpBL, bpSoft, bpPS, apiOn) + tReset)
	s.Writeln("")
}

func usersRemove(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users remove <username>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if username == s.user.Username {
		s.Writeln("[97mYou cannot remove yourself.\033[97m")
		return
	}
	if !guardLastAdmin(s, username) {
		return
	}
	if err := s.db.DeleteUser(username); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mRemoved '%s'.\033[97m", username))
	adminLog(s, "users_remove", fmt.Sprintf("target=%s", username))
}

func usersList(s *Session) {
	users, err := s.db.GetAllUsers()
	if err != nil {
		s.Writeln("[97mFailed to fetch users.\033[97m")
		return
	}
	headers := []string{"User", "Role", "Stat", "API", "MFA", "MaxT", "C", "Expiry"}
	now := time.Now().Unix()
	var rows [][]string
	for _, u := range users {
		role := "User"
		if u.Admin {
			role = "Admin"
		} else if u.Mod {
			role = "Mod"
		} else if u.Reseller {
			role = "Rslr"
		} else if u.VIP {
			role = "VIP"
		}
		st := "OK"
		if u.Banned {
			st = "Ban"
		} else if u.Locked {
			st = "Lck"
		}
		api := "off"
		if u.APIAccess {
			api = "on"
		}
		mfaCol := "off"
		if u.MFAEnabled {
			mfaCol = "on"
			if strings.TrimSpace(u.MFASecret) != "" {
				mfaCol = "on+"
			}
		}
		var exp string
		if u.Expire == 0 {
			exp = "Never"
		} else if now >= u.Expire {
			exp = "EXP"
		} else {
			exp = fmt.Sprintf("%dd", (u.Expire-now)/86400)
		}
		rows = append(rows, []string{
			u.Username,
			role,
			st,
			api,
			mfaCol,
			fmt.Sprintf("%d", u.MaxTime),
			fmt.Sprintf("%d", u.Concurrents),
			exp,
		})
	}
	s.writeSimpleTable(headers, rows)
}

func usersInfo(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users info <username>\033[97m")
		return
	}
	uname, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	u, err := s.db.GetUser(uname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.Writeln("[97mUser not found.\033[97m")
		} else {
			s.Writeln("[97mDatabase error.\033[97m")
		}
		return
	}
	yesNo := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	now := time.Now().Unix()
	var expVal string
	if u.Expire == 0 {
		expVal = "Never (no expiry)"
	} else if now >= u.Expire {
		expVal = "EXPIRED " + time.Unix(u.Expire, 0).Format(time.RFC1123)
	} else {
		expVal = time.Unix(u.Expire, 0).Format(time.RFC1123) + fmt.Sprintf(" (%dd left)", (u.Expire-now)/86400)
	}
	headers := []string{"Field", "Value"}
	rows := [][]string{
		{"Username", u.Username},
		{"User ID", fmt.Sprintf("%d", u.ID)},
		{"Must change password", yesNo(u.MustChangePassword)},
		{"API access", yesNo(u.APIAccess)},
		{"MFA enabled", yesNo(u.MFAEnabled)},
		{"TOTP linked", yesNo(strings.TrimSpace(u.MFASecret) != "")},
		{"VIP", yesNo(u.VIP)},
		{"Reseller", yesNo(u.Reseller)},
		{"Mod", yesNo(u.Mod)},
		{"Admin", yesNo(u.Admin)},
		{"Bypass blacklist", yesNo(u.BypassBlacklist)},
		{"Bypass softmax time", yesNo(u.BypassSoftMaxtime)},
		{"Bypass powersaving", yesNo(u.BypassPowersaving)},
		{"Max time (sec)", fmt.Sprintf("%d", u.MaxTime)},
		{"Concurrents", fmt.Sprintf("%d", u.Concurrents)},
		{"Theme", u.Theme},
		{"Banned", yesNo(u.Banned)},
		{"Locked", yesNo(u.Locked)},
		{"Created", time.Unix(u.TimeCreated, 0).Format(time.RFC1123)},
		{"Created by", u.CreatedBy},
		{"Expiry", expVal},
	}
	s.writeSimpleTable(headers, rows)
}

func usersRename(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users rename <old_username> <new_username>\033[97m")
		return
	}
	oldName, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	newName, err := ValidateUsername(args[1])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if oldName == newName {
		s.Writeln("[97mNames are identical.\033[97m")
		return
	}
	if _, err := s.db.GetUser(newName); err == nil {
		s.Writeln("[97mTarget username already exists.\033[97m")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		s.Writeln("[97mDatabase error.\033[97m")
		return
	}
	if err := s.db.RenameUser(oldName, newName); err != nil {
		writeDBErr(s, err)
		return
	}
	if oldName == s.user.Username {
		s.user.Username = newName
	}
	s.Writeln(fmt.Sprintf("[97mRenamed '%s' -> '%s'.\033[97m", oldName, newName))
	adminLog(s, "users_rename", fmt.Sprintf("%s->%s", oldName, newName))
}

func usersBan(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users ban <username>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if username == s.user.Username {
		s.Writeln("[97mYou cannot ban yourself.\033[97m")
		return
	}
	if !guardLastAdmin(s, username) {
		return
	}
	if err := s.db.SetBanned(username, true); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mBanned '%s'.\033[97m", username))
	adminLog(s, "users_ban", fmt.Sprintf("target=%s", username))
}

func usersUnban(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users unban <username>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if err := s.db.SetBanned(username, false); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mUnbanned '%s'.\033[97m", username))
	adminLog(s, "users_unban", fmt.Sprintf("target=%s", username))
}

func usersLock(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users lock <username>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if username == s.user.Username {
		s.Writeln("[97mYou cannot lock yourself.\033[97m")
		return
	}
	if !guardLastAdmin(s, username) {
		return
	}
	if err := s.db.SetLocked(username, true); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mLocked '%s'.\033[97m", username))
	adminLog(s, "users_lock", fmt.Sprintf("target=%s", username))
}

func usersUnlock(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users unlock <username>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	if err := s.db.SetLocked(username, false); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mUnlocked '%s'.\033[97m", username))
	adminLog(s, "users_unlock", fmt.Sprintf("target=%s", username))
}

func usersExtend(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users extend <username> <days>\033[97m")
		return
	}
	uname, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	days, err := strconv.Atoi(args[1])
	if err != nil || days <= 0 {
		s.Writeln("[97mDays must be a positive integer.\033[97m")
		return
	}
	if err := s.db.ExtendExpiryByDays(uname, days); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.Writeln("[97mUser not found.\033[97m")
			return
		}
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mExtended '%s' by %d day(s).\033[97m", uname, days))
	adminLog(s, "users_extend", fmt.Sprintf("target=%s days=%d", uname, days))
}

func usersExtendAll(s *Session, args []string) {
	if len(args) < 1 {
		s.Writeln("[97mUsage: users extendall <days>\033[97m")
		s.Writeln("[97m  Adds days to every account with a finite expiry (skip lifetime expire=0).\033[97m")
		return
	}
	days, err := strconv.Atoi(args[0])
	if err != nil || days <= 0 {
		s.Writeln("[97mDays must be a positive integer.\033[97m")
		return
	}
	n, err := s.db.ExtendAllUsersExpiryDays(days)
	if err != nil {
		s.Writeln(fmt.Sprintf("[97m%s\033[97m", err.Error()))
		return
	}
	s.Writeln(fmt.Sprintf("[97mUpdated %d row(s). All finite plans extended by %d day(s).\033[97m", n, days))
	adminLog(s, "users_extendall", fmt.Sprintf("days=%d rows=%d", days, n))
}

func usersSetMaxTime(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users setmaxtime <username> <seconds>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	maxTime, err := strconv.Atoi(args[1])
	if err != nil || maxTime < 0 {
		s.Writeln("[97mInvalid seconds.\033[97m")
		return
	}
	if err := s.db.SetMaxTime(username, maxTime); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln("[97mMax time updated.\033[97m")
	adminLog(s, "users_setmaxtime", fmt.Sprintf("target=%s v=%d", username, maxTime))
}

func usersSetConc(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users setconc <username> <amount>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	conc, err := strconv.Atoi(args[1])
	if err != nil || conc < 0 {
		s.Writeln("[97mInvalid amount.\033[97m")
		return
	}
	if err := s.db.SetConcurrents(username, conc); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln("[97mConcurrents updated.\033[97m")
	adminLog(s, "users_setconc", fmt.Sprintf("target=%s v=%d", username, conc))
}

func usersSetExpiry(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users setexpiry <username> <days>\033[97m")
		s.Writeln("[97m  0 = lifetime. Otherwise plan ends N days from now.\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	days, err := strconv.Atoi(args[1])
	if err != nil || days < 0 {
		s.Writeln("[97mInvalid days.\033[97m")
		return
	}
	if err := s.db.SetExpiryDaysFromNow(username, days); err != nil {
		writeDBErr(s, err)
		return
	}
	if days == 0 {
		s.Writeln(fmt.Sprintf("[97m'%s' -> no expiry (lifetime).\033[97m", username))
	} else {
		s.Writeln(fmt.Sprintf("[97m'%s' -> expires in %d day(s) from now.\033[97m", username, days))
	}
	adminLog(s, "users_setexpiry", fmt.Sprintf("target=%s days=%d", username, days))
}

func usersSetTheme(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users settheme <username> <theme>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	theme := strings.ToLower(args[1])
	if s.config.FindTheme(theme) == nil {
		s.Writeln("[97mTheme not found.\033[97m")
		return
	}
	if err := s.db.SetTheme(username, theme); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln("[97mTheme updated.\033[97m")
	adminLog(s, "users_settheme", fmt.Sprintf("target=%s t=%s", username, theme))
}

func usersResetPW(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users resetpw <username> <new_password>\033[97m")
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	newPass := args[1]
	hash := sha256.Sum256([]byte(newPass))
	hashStr := hex.EncodeToString(hash[:])
	if err := s.db.UpdatePassword(username, hashStr); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln("[97mPassword reset.\033[97m")
	adminLog(s, "users_resetpw", fmt.Sprintf("target=%s", username))
}

func usersSetRole(s *Session, args []string, role string) {
	if len(args) < 1 {
		s.Writeln(fmt.Sprintf("[97mUsage: users set%s <username>\033[97m", role))
		return
	}
	username, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	target, err := s.db.GetUser(username)
	if err != nil {
		s.Writeln("[97mUser not found.\033[97m")
		return
	}
	var currentVal bool
	switch role {
	case "admin":
		currentVal = target.Admin
	case "mod":
		currentVal = target.Mod
	case "reseller":
		currentVal = target.Reseller
	case "vip":
		currentVal = target.VIP
	}
	newVal := !currentVal
	if role == "admin" && currentVal && !newVal {
		if !guardLastAdmin(s, username) {
			return
		}
	}
	if err := s.db.SetRole(username, role, newVal); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97m%s %s for '%s'.\033[97m", capitalize(role), map[bool]string{true: "enabled", false: "disabled"}[newVal], username))
	adminLog(s, "users_set"+role, fmt.Sprintf("target=%s v=%v", username, newVal))
}

func usersBypass(s *Session, args []string) {
	if len(args) < 3 {
		s.Writeln("[97mUsage: users bypass <username> <bl|soft|ps|all> <on|off>\033[97m")
		return
	}
	uname, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	which := strings.ToLower(args[1])
	val, ok := parseOnOff(args[2])
	if !ok {
		s.Writeln("[97mUse on or off.\033[97m")
		return
	}
	var e error
	switch which {
	case "bl", "blacklist":
		e = s.db.SetBypassBlacklist(uname, val)
	case "soft", "softmax":
		e = s.db.SetBypassSoftmaxtime(uname, val)
	case "ps", "powersaving", "power":
		e = s.db.SetBypassPowersaving(uname, val)
	case "all":
		e = s.db.SetBypassBlacklist(uname, val)
		if e == nil {
			e = s.db.SetBypassSoftmaxtime(uname, val)
		}
		if e == nil {
			e = s.db.SetBypassPowersaving(uname, val)
		}
	default:
		s.Writeln("[97mUse bl, soft, ps, or all.\033[97m")
		return
	}
	if e != nil {
		writeDBErr(s, e)
		return
	}
	s.Writeln("[97mBypass flags updated.\033[97m")
	adminLog(s, "users_bypass", fmt.Sprintf("target=%s %s=%v", uname, which, val))
}

func usersSetAPI(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users api <username> <on|off>\033[97m")
		return
	}
	uname, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	val, ok := parseOnOff(args[1])
	if !ok {
		s.Writeln("[97mUse on or off.\033[97m")
		return
	}
	if err := s.db.SetAPIAccess(uname, val); err != nil {
		writeDBErr(s, err)
		return
	}
	s.Writeln(fmt.Sprintf("[97mAPI access for '%s': %v\033[97m", uname, val))
	adminLog(s, "users_api", fmt.Sprintf("target=%s v=%v", uname, val))
}

func usersMFA(s *Session, args []string) {
	if len(args) < 2 {
		s.Writeln("[97mUsage: users mfa <username> <on|off|reset>\033[97m")
		s.Writeln("[97m  on: require TOTP for this user (unless already forced for everyone in config).\033[97m")
		s.Writeln("[97m  off: clear per-user requirement (config force_all_users still applies).\033[97m")
		s.Writeln("[97m  reset: wipe linked authenticator; next login shows a new QR when MFA is required.\033[97m")
		return
	}
	uname, err := ValidateUsername(args[0])
	if err != nil {
		s.Writeln("[97m" + err.Error() + "\033[97m")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(args[1]))
	switch mode {
	case "on":
		if err := s.db.SetMFAEnabled(uname, true); err != nil {
			writeDBErr(s, err)
			return
		}
		s.Writeln(fmt.Sprintf("[97mMFA enabled for '%s'.\033[97m", uname))
		adminLog(s, "users_mfa", fmt.Sprintf("target=%s on", uname))
	case "off":
		if err := s.db.SetMFAEnabled(uname, false); err != nil {
			writeDBErr(s, err)
			return
		}
		s.Writeln(fmt.Sprintf("[97mPer-user MFA disabled for '%s'. If settings.mfa.force_all_users is true, TOTP is still required.\033[97m", uname))
		adminLog(s, "users_mfa", fmt.Sprintf("target=%s off", uname))
	case "reset":
		if err := s.db.SetUserMFASecret(uname, ""); err != nil {
			writeDBErr(s, err)
			return
		}
		s.Writeln(fmt.Sprintf("[97mAuthenticator secret reset for '%s'.\033[97m", uname))
		adminLog(s, "users_mfa", fmt.Sprintf("target=%s reset", uname))
	default:
		s.Writeln("[97mUse on, off, or reset.\033[97m")
	}
}

func adminBroadcast(s *Session, args []string) {
	if len(args) == 0 {
		s.Writeln("[97mUsage: broadcast <message>\033[97m")
		return
	}
	message := strings.Join(args, " ")
	s.server.BroadcastMessage(s.user.Username, message)
	adminLog(s, "broadcast", "sent")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func listPresets(cfg *Config) string {
	var names []string
	for _, p := range cfg.Presets {
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}

func adminLog(s *Session, action, details string) {
	logToFile("assets/logs/admin_logs.txt",
		fmt.Sprintf("[%s] admin=%s action=%s %s",
			time.Now().Format("2006-01-02 15:04:05"), s.user.Username, action, details))
}
