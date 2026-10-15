package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	Config     *Config
	configPath string
	configMu   sync.RWMutex
	DB         *Database
	Attacks    *AttackManager
	Webhooks   *WebhookManager
	sessions   []*Session
	sessionsMu sync.RWMutex
}

func NewServer(cfg *Config, db *Database, atk *AttackManager, wh *WebhookManager, configPath string) *Server {
	return &Server{
		Config:     cfg,
		configPath: configPath,
		DB:         db,
		Attacks:    atk,
		Webhooks:   wh,
	}
}

// GetConfig returns the current config (live pointer; reload-safe for callers that read fields once per call).
func (s *Server) GetConfig() *Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.Config
}

// ReloadConfig loads assets/config.json (or the path given at startup) and applies it without restarting listeners.
// SSH/API/website bind addresses and database credentials are not re-applied; change methods, themes, settings, webhooks, etc.
func (s *Server) ReloadConfig() error {
	if strings.TrimSpace(s.configPath) == "" {
		return fmt.Errorf("config path not set")
	}
	newCfg, err := LoadConfig(s.configPath)
	if err != nil {
		return err
	}
	s.applyLoadedConfig(newCfg)
	return nil
}

func (s *Server) applyLoadedConfig(newCfg *Config) {
	s.configMu.Lock()
	s.Config = newCfg
	s.configMu.Unlock()

	s.Attacks.SetConfig(newCfg)
	s.Webhooks.SetConfig(newCfg.Webhooks)

	s.sessionsMu.Lock()
	for _, sess := range s.sessions {
		sess.config = newCfg
	}
	s.sessionsMu.Unlock()
}

// WatchConfigAutoReload polls the config file when settings.general.auto_reload is true and reloads on mtime change.
func (s *Server) WatchConfigAutoReload() {
	path := s.configPath
	if strings.TrimSpace(path) == "" {
		return
	}
	var lastMod time.Time
	if st, err := os.Stat(path); err == nil {
		lastMod = st.ModTime()
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cfg := s.GetConfig()
		if cfg == nil || !cfg.Settings.General.AutoReload {
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !st.ModTime().After(lastMod) {
			continue
		}
		lastMod = st.ModTime()
		if err := s.ReloadConfig(); err != nil {
			log.Printf("[!] config autoreload failed: %v", err)
			continue
		}
		if st2, err := os.Stat(path); err == nil {
			lastMod = st2.ModTime()
		}
		log.Printf("[+] config autoreloaded (%s)", path)
	}
}

func (s *Server) AddSession(sess *Session) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	filtered := s.sessions[:0]
	for _, ex := range s.sessions {
		if ex.user.Username == sess.user.Username {
			ch := ex.channel
			go func() { _ = ch.Close() }()
			continue
		}
		filtered = append(filtered, ex)
	}
	s.sessions = append(filtered, sess)
}

func (s *Server) findSessionByUsername(username string) *Session {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	for _, ex := range s.sessions {
		if ex.user.Username == username {
			return ex
		}
	}
	return nil
}

// promptDisconnectOtherSession asks to take over if the same user is already online. Returns false to abort login.
func (s *Server) promptDisconnectOtherSession(newSess *Session) bool {
	other := s.findSessionByUsername(newSess.user.Username)
	if other == nil {
		return true
	}

	newSess.Writeln("")
	newSess.Writeln("\033[97mThis account already has an open session.\033[0;97m")
	newSess.Writeln("\033[97mPress Y to disconnect your other session and continue, or any other key to abort.\033[0;97m")

	buf := make([]byte, 1)
	n, err := newSess.channel.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	ch := buf[0]
	newSess.writeMu.Lock()
	_, _ = newSess.channel.Write([]byte{ch, '\r', '\n'})
	newSess.writeMu.Unlock()

	if ch != 'y' && ch != 'Y' {
		newSess.Writeln("\033[97mLogin aborted.\033[0;97m")
		return false
	}
	_ = other.channel.Close()
	newSess.Writeln("\033[97mOther session disconnected.\033[0;97m")
	newSess.Writeln("")
	return true
}

func (s *Server) RemoveSession(sess *Session) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for i, existing := range s.sessions {
		if existing == sess {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			return
		}
	}
}

func (s *Server) GetOnlineCount() int {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return len(s.sessions)
}

func (s *Server) BroadcastMessage(sender, message string) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	bannerPath := "branding/broadcast.txt"
	ctx := BuildBroadcastContext(sender, message)

	for _, sess := range s.sessions {
		banner := sess.ReadThemedBanner(bannerPath)
		rendered := RenderTermFX(banner, ctx)
		sess.WriteRenderedTermFX("\r\n"+rendered+"\r\n", 0, false)
		sess.ShowPrompt()
	}
}

// normalizeSSHAuthBanner strips a leading ASCII "|" (and one following space/tab) from each line.
// Fixes copy/paste from clients that include a gutter bar in the banner source file.
func normalizeSSHAuthBanner(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.HasPrefix(ln, "|") {
			ln = strings.TrimPrefix(ln, "|")
			ln = strings.TrimPrefix(ln, " ")
			ln = strings.TrimPrefix(ln, "\t")
		}
		lines[i] = ln
	}
	return strings.Join(lines, "\r\n")
}

func (s *Server) sshPreAuthBanner(conn ssh.ConnMetadata) string {
	_ = conn
	cfg := s.GetConfig()
	if cfg == nil {
		return ""
	}
	sub := cfg.Settings.Login.SanitizedSSHBanner()
	if sub == "" {
		return ""
	}
	raw := ReadBannerFile("assets/banners/default/" + sub)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	out := RenderTermFX(raw, BuildPreAuthBannerContext(cfg))
	return normalizeSSHAuthBanner(out)
}

func (s *Server) Start() error {
	sshConfig := &ssh.ServerConfig{
		BannerCallback: s.sshPreAuthBanner,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			uname, err := ValidateUsername(conn.User())
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}

			hash := sha256.Sum256(password)
			hashStr := hex.EncodeToString(hash[:])

			user, err := s.DB.GetUser(uname)
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			if len(user.Password) != len(hashStr) || subtle.ConstantTimeCompare([]byte(user.Password), []byte(hashStr)) != 1 {
				return nil, fmt.Errorf("invalid credentials")
			}
			if user.Banned {
				return nil, fmt.Errorf("account banned")
			}
			if user.Locked {
				return nil, fmt.Errorf("account locked")
			}
			// expire == 0 means no expiry (lifetime). Otherwise Unix ts must be in the future for non-admins.
			if !user.Admin && user.Expire > 0 && time.Now().Unix() >= user.Expire {
				return nil, fmt.Errorf("account expired")
			}

			return &ssh.Permissions{
				Extensions: map[string]string{
					"username": user.Username,
				},
			}, nil
		},
	}

	keyBytes, err := os.ReadFile(s.Config.ServerConfig.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	sshConfig.AddHostKey(signer)

	addr := s.Config.ServerConfig.ResolveSSHListenAddr()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("[!] Failed to accept connection: %v", err)
			continue
		}
		go s.handleConnection(tcpConn, sshConfig)
	}
}

func (s *Server) handleConnection(tcpConn net.Conn, sshConfig *ssh.ServerConfig) {
	defer tcpConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	if s.GetConfig().Settings.General.LogIPs {
		log.Printf("[+] Login: %s from %s", sshConn.User(), tcpConn.RemoteAddr().String())
	}

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleChannel(channel, requests, sshConn, tcpConn.RemoteAddr().String())
	}
}

func (s *Server) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, conn *ssh.ServerConn, clientIP string) {
	defer channel.Close()

	uname, err := ValidateUsername(conn.User())
	if err != nil {
		channel.Write([]byte("Invalid username.\r\n"))
		return
	}
	user, err := s.DB.GetUser(uname)
	if err != nil {
		channel.Write([]byte("Failed to load user data.\r\n"))
		return
	}

	session := &Session{
		user:     user,
		channel:  channel,
		server:   s,
		config:   s.GetConfig(),
		db:       s.DB,
		attacks:  s.Attacks,
		webhooks: s.Webhooks,
		clientIP: clientIP,
		done:     make(chan struct{}),
		width:    80,
		height:   24,
	}

	shellStarted := make(chan bool, 1)

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				parsePtyReq(req, session)
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
				select {
				case shellStarted <- true:
				default:
				}
			case "window-change":
				parseWinChange(req, session)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	select {
	case <-shellStarted:
	case <-time.After(10 * time.Second):
		return
	}

	if !s.promptDisconnectOtherSession(session) {
		return
	}
	if !session.RunMFALogin() {
		return
	}

	s.AddSession(session)
	session.Run()
	s.RemoveSession(session)
}

func parsePtyReq(req *ssh.Request, session *Session) {
	if len(req.Payload) < 4 {
		return
	}
	termLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
	offset := 4 + termLen
	if len(req.Payload) < offset+8 {
		return
	}
	session.width = int(binary.BigEndian.Uint32(req.Payload[offset : offset+4]))
	session.height = int(binary.BigEndian.Uint32(req.Payload[offset+4 : offset+8]))
}

func parseWinChange(req *ssh.Request, session *Session) {
	if len(req.Payload) < 8 {
		return
	}
	session.width = int(binary.BigEndian.Uint32(req.Payload[0:4]))
	session.height = int(binary.BigEndian.Uint32(req.Payload[4:8]))
}
