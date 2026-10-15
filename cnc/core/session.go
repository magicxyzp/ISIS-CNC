package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// defaultPasswordHash is SHA-256 hex of "changeme" (seed password).
const defaultPasswordHash = "057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"

const maxCmdHistory = 200

// termFXSleepRE matches <<sleep(ms)>> from GIF-to-terminal exporters (optional spaces).
var termFXSleepRE = regexp.MustCompile(`<<\s*sleep\s*\(\s*(\d+)\s*\)\s*>>`)

type Session struct {
	user     *User
	channel  ssh.Channel
	server   *Server
	config   *Config
	db       *Database
	attacks  *AttackManager
	webhooks *WebhookManager
	clientIP string
	done     chan struct{}
	width    int
	height   int
	writeMu  sync.Mutex // ssh.Channel writes must not interleave or OSC/title sequences break
	cmdHistory []string  // previous shell lines (oldest first), capped at maxCmdHistory
	// usersCmdResizeActive: any `users` subcommand sent CSI 8;29;112t; next non-users command sends 8;24;80t.
	usersCmdResizeActive bool
}

func (s *Session) Write(data string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = s.channel.Write([]byte(data))
}

func (s *Session) Writeln(data string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = s.channel.Write([]byte(data + "\r\n"))
}

// WriteChunked sends large ANSI payloads in pieces. Must hold writeMu for the whole operation so
// titleUpdater OSC sequences cannot inject between chunks (that breaks truecolor/CSI parsing).
func (s *Session) WriteChunked(data string, maxChunk int) {
	if maxChunk <= 0 {
		maxChunk = 16 * 1024
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	write := func(p string) {
		if p == "" {
			return
		}
		_, _ = s.channel.Write([]byte(p))
	}
	if len(data) <= maxChunk {
		write(data)
		return
	}
	for len(data) > 0 {
		n := maxChunk
		if n > len(data) {
			n = len(data)
		}
		if n < len(data) {
			if i := strings.LastIndexByte(data[:n], '\n'); i >= n/4 {
				n = i + 1
			}
		}
		write(data[:n])
		data = data[n:]
	}
}

// stripLeadingRIS removes ESC c (full terminal reset). GIF-to-terminal exporters often prepend it;
// it can leave the session in a state where the following splash never paints correctly.
func stripLeadingRIS(s string) string {
	for strings.HasPrefix(s, "\033c") { // RIS: ESC (0x1B) + 'c'
		s = s[2:]
	}
	return s
}

const (
	defaultRenderedTermFXChunk = 20 * 1024
	maxTermFXSleepStepMs       = 10000  // per <<sleep(ms)>> cap
	maxTermFXAnimationWait     = 180000 // total pause budget per write (ms)
)

// WriteRenderedTermFX writes already-rendered TermFX output (e.g. from RenderBanner), pausing at each
// <<sleep(ms)>> tag using the millisecond value from the file. Holds writeMu for the whole run so OSC
// title updates cannot splice into ANSI mid-animation. If appendTrailingNewline, appends \r\n after the payload (Writeln semantics).
func (s *Session) WriteRenderedTermFX(out string, maxChunk int, appendTrailingNewline bool) {
	if maxChunk <= 0 {
		maxChunk = defaultRenderedTermFXChunk
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	writePart := func(p string) {
		for len(p) > 0 {
			n := maxChunk
			if n > len(p) {
				n = len(p)
			}
			if n < len(p) {
				if i := strings.LastIndexByte(p[:n], '\n'); i >= n/4 {
					n = i + 1
				}
			}
			_, _ = s.channel.Write([]byte(p[:n]))
			p = p[n:]
		}
	}

	var totalSleptMs int64
	rest := out
	for {
		loc := termFXSleepRE.FindStringSubmatchIndex(rest)
		if loc == nil {
			writePart(rest)
			break
		}
		writePart(rest[:loc[0]])
		ms, err := strconv.Atoi(rest[loc[2]:loc[3]])
		if err != nil || ms < 0 {
			ms = 0
		}
		if ms > maxTermFXSleepStepMs {
			ms = maxTermFXSleepStepMs
		}
		adj := ms
		if int64(adj)+totalSleptMs > maxTermFXAnimationWait {
			adj = int(maxTermFXAnimationWait - totalSleptMs)
			if adj < 0 {
				adj = 0
			}
		}
		if adj > 0 {
			time.Sleep(time.Duration(adj) * time.Millisecond)
			totalSleptMs += int64(adj)
		}
		rest = rest[loc[1]:]
		if totalSleptMs >= maxTermFXAnimationWait {
			writePart(rest)
			break
		}
	}
	if appendTrailingNewline {
		_, _ = s.channel.Write([]byte("\r\n"))
	}
}

// effectiveTheme returns a non-empty theme name for banner paths.
func (s *Session) effectiveTheme() string {
	t := strings.TrimSpace(s.user.Theme)
	if t == "" {
		return "default"
	}
	return t
}

// ReadThemedBanner loads assets/banners/{theme}/{subpath}, falling back to theme "default" if missing.
func (s *Session) ReadThemedBanner(subpath string) string {
	theme := s.effectiveTheme()
	path := fmt.Sprintf("assets/banners/%s/%s", theme, subpath)
	content := ReadBannerFile(path)
	if content != "" || theme == "default" {
		return content
	}
	return ReadBannerFile(fmt.Sprintf("assets/banners/default/%s", subpath))
}

func (s *Session) BannerPath(subpath string) string {
	return fmt.Sprintf("assets/banners/%s/%s", s.effectiveTheme(), subpath)
}

func (s *Session) RenderBanner(subpath string, extraCtx map[string]string) string {
	content := s.ReadThemedBanner(subpath)
	if content == "" {
		return ""
	}
	ctx := BuildUserContext(s.user, s.server, s.db)
	for k, v := range extraCtx {
		ctx[k] = v
	}
	return RenderTermFX(content, ctx)
}

func (s *Session) RenderBannerPath(path string, extraCtx map[string]string) string {
	themePath := strings.ReplaceAll(path, "{THEME}", s.effectiveTheme())
	content := ReadBannerFile(themePath)
	if content == "" && s.effectiveTheme() != "default" {
		fallback := strings.ReplaceAll(path, "{THEME}", "default")
		content = ReadBannerFile(fallback)
	}
	if content == "" {
		return ""
	}
	ctx := BuildUserContext(s.user, s.server, s.db)
	for k, v := range extraCtx {
		ctx[k] = v
	}
	return RenderTermFX(content, ctx)
}

func (s *Session) ShowPrompt() {
	banner := s.RenderBanner("branding/prompt.txt", nil)
	s.Write(banner)
}

func (s *Session) ClearScreen() {
	s.Write("\033[2J\033[H")
}

// resizeTerminalCSI sends xterm-style CSI 8;rows;cols (character cell size). Many SSH clients honor it; some do not.
func (s *Session) resizeTerminalCSI(rows, cols int) {
	if s == nil || rows <= 0 || cols <= 0 {
		return
	}
	s.Write(fmt.Sprintf("\033[8;%d;%dt", rows, cols))
}

// readCsiFinalByte reads the final byte of a CSI sequence (0x40?0x7E) after ESC [ has been consumed.
func readCsiFinalByte(r io.Reader) (byte, error) {
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		if b[0] >= 0x40 && b[0] <= 0x7E {
			return b[0], nil
		}
	}
}

func (s *Session) redrawPromptLine(line []byte) {
	s.redrawPromptLineCursor(line, len(line))
}

// redrawPromptLineCursor redraws the prompt and line and places the cursor at pos (0..len(line)).
func (s *Session) redrawPromptLineCursor(line []byte, pos int) {
	if pos > len(line) {
		pos = len(line)
	}
	if pos < 0 {
		pos = 0
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	prompt := s.RenderBanner("branding/prompt.txt", nil)
	_, _ = s.channel.Write([]byte("\r\033[K"))
	_, _ = s.channel.Write([]byte(prompt))
	_, _ = s.channel.Write(line)
	for i := len(line) - pos; i > 0; i-- {
		_, _ = s.channel.Write([]byte("\033[D"))
	}
}

func (s *Session) appendHistory(cmd string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	s.cmdHistory = append(s.cmdHistory, cmd)
	if len(s.cmdHistory) > maxCmdHistory {
		s.cmdHistory = s.cmdHistory[len(s.cmdHistory)-maxCmdHistory:]
	}
}

func (s *Session) ReadLine() (string, error) {
	line := make([]byte, 0, 128)
	pos := 0
	histIdx := len(s.cmdHistory)
	buf := make([]byte, 1)
	for {
		n, err := s.channel.Read(buf)
		if err != nil || n == 0 {
			return "", err
		}
		b := buf[0]
		switch {
		case b == '\r' || b == '\n':
			s.writeMu.Lock()
			_, _ = s.channel.Write([]byte("\r\n"))
			s.writeMu.Unlock()
			return strings.TrimSpace(string(line)), nil
		case b == 127 || b == '\b':
			if histIdx != len(s.cmdHistory) {
				histIdx = len(s.cmdHistory)
			}
			if pos > 0 {
				wasAtEnd := pos == len(line)
				line = append(line[:pos-1], line[pos:]...)
				pos--
				if wasAtEnd {
					s.writeMu.Lock()
					_, _ = s.channel.Write([]byte("\b \b"))
					s.writeMu.Unlock()
				} else {
					s.redrawPromptLineCursor(line, pos)
				}
			}
		case b == 3: // Ctrl+C
			s.writeMu.Lock()
			_, _ = s.channel.Write([]byte("\r\n"))
			s.writeMu.Unlock()
			return "", nil
		case b == 4: // Ctrl+D
			return "", fmt.Errorf("disconnect")
		case b == 27: // CSI (ESC [ ?) or SS3 (ESC O) arrow keys
			b2 := make([]byte, 1)
			if _, err := io.ReadFull(s.channel, b2); err != nil {
				return "", err
			}
			var final byte
			switch b2[0] {
			case '[':
				var err error
				final, err = readCsiFinalByte(s.channel)
				if err != nil {
					return "", err
				}
			case 'O': // e.g. xterm SS3: ESC O A / ESC O B / C / D
				b3 := make([]byte, 1)
				if _, err := io.ReadFull(s.channel, b3); err != nil {
					return "", err
				}
				final = b3[0]
			default:
				continue
			}
			nh := len(s.cmdHistory)
			switch final {
			case 'A': // up ? older command
				if nh == 0 {
					continue
				}
				if histIdx == nh {
					histIdx = nh - 1
				} else if histIdx > 0 {
					histIdx--
				}
				line = append(line[:0], s.cmdHistory[histIdx]...)
				pos = len(line)
				s.redrawPromptLineCursor(line, pos)
			case 'B': // down ? newer command or blank line
				if nh == 0 {
					continue
				}
				if histIdx < nh-1 {
					histIdx++
					line = append(line[:0], s.cmdHistory[histIdx]...)
					pos = len(line)
					s.redrawPromptLineCursor(line, pos)
				} else if histIdx == nh-1 {
					histIdx = nh
					line = line[:0]
					pos = 0
					s.redrawPromptLineCursor(line, pos)
				}
			case 'C': // right
				if pos < len(line) {
					pos++
					s.writeMu.Lock()
					_, _ = s.channel.Write([]byte("\033[C"))
					s.writeMu.Unlock()
				}
			case 'D': // left
				if pos > 0 {
					pos--
					s.writeMu.Lock()
					_, _ = s.channel.Write([]byte("\033[D"))
					s.writeMu.Unlock()
				}
			}
		case b == 21: // Ctrl+U ? clear line
			if histIdx != len(s.cmdHistory) {
				histIdx = len(s.cmdHistory)
			}
			line = line[:0]
			pos = 0
			s.redrawPromptLineCursor(line, pos)
		case b >= 32 && b < 127:
			if histIdx != len(s.cmdHistory) {
				histIdx = len(s.cmdHistory)
			}
			if pos == len(line) {
				line = append(line, b)
				pos++
				s.writeMu.Lock()
				_, _ = s.channel.Write([]byte{b})
				s.writeMu.Unlock()
			} else {
				line = append(line[:pos], append([]byte{b}, line[pos:]...)...)
				pos++
				s.redrawPromptLineCursor(line, pos)
			}
		}
	}
}

func (s *Session) ReadPassword() (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := s.channel.Read(buf)
		if err != nil || n == 0 {
			return "", err
		}
		b := buf[0]
		switch {
		case b == '\r' || b == '\n':
			s.writeMu.Lock()
			_, _ = s.channel.Write([]byte("\r\n"))
			s.writeMu.Unlock()
			return string(line), nil
		case b == 127 || b == '\b':
			if len(line) > 0 {
				line = line[:len(line)-1]
				s.writeMu.Lock()
				_, _ = s.channel.Write([]byte("\b \b"))
				s.writeMu.Unlock()
			}
		case b >= 32 && b < 127:
			line = append(line, b)
			s.writeMu.Lock()
			_, _ = s.channel.Write([]byte("*"))
			s.writeMu.Unlock()
		}
	}
}

func (s *Session) mustChangePasswordNow() bool {
	if s.user.MustChangePassword {
		return true
	}
	return s.user.Password == defaultPasswordHash
}

// forcePasswordChange blocks the shell until the user sets a new password (first login or default password).
func (s *Session) forcePasswordChange() error {
	s.Writeln("")
	s.Writeln("\033[97m[!] You must set a new password before continuing.\033[0;97m")
	s.Writeln("")

	for {
		s.Write("\033[0;97mNew password: \033[0m")
		newPass, err := s.ReadPassword()
		if err != nil {
			return err
		}
		newPass = strings.TrimSpace(newPass)
		if newPass == "" {
			s.Writeln("\033[97mPassword cannot be empty.\033[0;97m")
			continue
		}

		s.Write("\033[0;97mConfirm password: \033[0m")
		confirm, err := s.ReadPassword()
		if err != nil {
			return err
		}
		confirm = strings.TrimSpace(confirm)

		if newPass != confirm {
			s.Writeln("\033[97mPasswords do not match. Try again.\033[0;97m")
			continue
		}

		hash := sha256.Sum256([]byte(newPass))
		hashStr := hex.EncodeToString(hash[:])
		if err := s.db.UpdatePassword(s.user.Username, hashStr); err != nil {
			s.Writeln("\033[97mFailed to save password. Try again.\033[0;97m")
			continue
		}
		s.user.Password = hashStr
		s.user.MustChangePassword = false
		s.Writeln("")
		s.Writeln("\033[97m[+] Password updated. You can use the panel now.\033[0;97m")
		s.Writeln("")
		return nil
	}
}

func (s *Session) SetTitle(title string) {
	// Must not use Sprintf: title can contain '%'. Payload must not include ESC/BEL or it breaks OSC.
	title = strings.ReplaceAll(title, "\007", "")
	title = strings.ReplaceAll(title, "\033", "")
	// OSC 0 = icon+window (xterm), OSC 2 = window title only (many terminals). BEL + ESC\ ST for client quirks.
	seq := "\033]0;" + title + "\007\033]2;" + title + "\007\033]0;" + title + "\033\\"
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = s.channel.Write([]byte(seq))
}

func (s *Session) Run() {
	defer func() {
		if s.usersCmdResizeActive {
			s.resizeTerminalCSI(24, 80)
		}
		close(s.done)
	}()

	go s.titleUpdater()

	splash := s.RenderBanner("branding/home-splash.txt", nil)
	if strings.TrimSpace(splash) != "" {
		s.WriteRenderedTermFX(splash, 0, false)
	}
	s.Writeln("")

	if s.mustChangePasswordNow() {
		if err := s.forcePasswordChange(); err != nil {
			return
		}
	}

	s.ShowPrompt()

	for {
		input, err := s.ReadLine()
		if err != nil {
			return
		}
		if input == "" {
			s.ShowPrompt()
			continue
		}
		s.appendHistory(input)
		if !s.EnsureLiveAccount() {
			return
		}
		HandleCommand(s, input)
		s.ShowPrompt()
	}
}

// EnsureLiveAccount reloads the user from the DB and ends the session if banned, locked, or expired.
func (s *Session) EnsureLiveAccount() bool {
	u, err := s.db.GetUser(s.user.Username)
	if err != nil {
		s.Writeln("[97mAccount lookup failed. Session closed.\033[97m")
		return false
	}
	s.user = u
	if u.Banned {
		s.Writeln("[97mYour account has been banned.\033[97m")
		return false
	}
	if u.Locked {
		s.Writeln("[97mYour account has been locked.\033[97m")
		return false
	}
	if !u.Admin && u.Expire > 0 && time.Now().Unix() >= u.Expire {
		s.Writeln("[97mYour plan has expired.\033[97m")
		return false
	}
	return true
}

func (s *Session) titleUpdater() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[!] title updater panic (titles disabled for this session): %v", err)
		}
	}()

	sleepMs := s.config.Settings.Title.SpinnerFrameMs
	if sleepMs <= 0 {
		sleepMs = s.config.Settings.Title.UpdateSleep
	}
	if sleepMs <= 0 {
		sleepMs = 500
	}

	const titleFakeBotsMin = 1000
	const titleFakeBotsMax = 1200

	spinIdx := 0

	tick := func() {
		titleTemplate := strings.TrimSpace(s.ReadThemedBanner("branding/title.txt"))
		if titleTemplate == "" {
			titleTemplate = "ISIS-C&C"
		}

		fakeBots := titleFakeBotsMin
		if titleFakeBotsMax > titleFakeBotsMin {
			fakeBots += rand.Intn(titleFakeBotsMax - titleFakeBotsMin + 1)
		}

		frames := ParseSpinnerFrames(s.ReadThemedBanner("branding/spinner.txt"))
		if len(frames) == 0 {
			frames = DefaultSpinnerFrames()
		}
		frame := SanitizeTitleSpinnerFrame(frames[spinIdx%len(frames)])
		if frame == "" {
			frame = DefaultSpinnerFrames()[0]
		}
		spinIdx++

		ctx := BuildTitleContext(s.user, s.server, s.db, frame, fakeBots)

		title := CollapseRenderedTitle(RenderTermFX(titleTemplate, ctx))
		if title == "" {
			title = "ISIS-C&C"
		}
		s.SetTitle(title)
	}

	// First title immediately so the bar updates before the first sleep (many clients never showed a ?before? state).
	tick()

	for {
		select {
		case <-s.done:
			return
		case <-time.After(time.Duration(sleepMs) * time.Millisecond):
		}
		tick()
	}
}

func (s *Session) RefreshUser() {
	updated, err := s.db.GetUser(s.user.Username)
	if err == nil {
		s.user = updated
	}
}
