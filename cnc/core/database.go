package core

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ErrUserNotFound is returned when an UPDATE/DELETE affects zero rows.
var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID                int
	Username          string
	Password          string
	VIP               bool
	Reseller          bool
	Mod               bool
	Admin             bool
	BypassPowersaving bool
	BypassBlacklist   bool
	BypassSoftMaxtime bool
	APIAccess         bool
	Theme             string
	MaxTime           int
	Concurrents       int
	Banned            bool
	Locked            bool
	TimeCreated       int64
	CreatedBy             string
	Expire                int64
	MustChangePassword    bool
	MFAEnabled            bool
	MFASecret             string
}

type AttackLog struct {
	ID       int
	Username string
	Host     string
	Port     int
	Duration int
	Method   string
	TimeSent int64
}

type Database struct {
	db *sql.DB
}

func intToBool(v int) bool { return v != 0 }
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func NewDatabase(cfg DatabaseConfig) (*Database, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=false",
		cfg.Username, cfg.Password, cfg.Host, cfg.Table)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Database{db: db}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var vip, reseller, mod, admin, bpPower, bpBlack, bpSoft, apiAcc, banned, locked, mustCh, mfaEn int
	err := row.Scan(
		&u.ID, &u.Username, &u.Password,
		&vip, &reseller, &mod, &admin,
		&bpPower, &bpBlack, &bpSoft,
		&apiAcc,
		&u.Theme, &u.MaxTime, &u.Concurrents,
		&banned, &locked, &u.TimeCreated, &u.CreatedBy, &u.Expire,
		&mustCh,
		&mfaEn, &u.MFASecret,
	)
	if err != nil {
		return nil, err
	}
	u.VIP = intToBool(vip)
	u.Reseller = intToBool(reseller)
	u.Mod = intToBool(mod)
	u.Admin = intToBool(admin)
	u.BypassPowersaving = intToBool(bpPower)
	u.BypassBlacklist = intToBool(bpBlack)
	u.BypassSoftMaxtime = intToBool(bpSoft)
	u.APIAccess = intToBool(apiAcc)
	u.Banned = intToBool(banned)
	u.Locked = intToBool(locked)
	u.MustChangePassword = intToBool(mustCh)
	u.MFAEnabled = intToBool(mfaEn)
	return &u, nil
}

const userColumns = "id, username, password, vip, reseller, `mod`, admin, bypass_powersaving, bypass_blacklist, bypass_softmaxtime, api_access, theme, max_time, concurrents, banned, locked, time_created, created_by, expire, must_change_password, mfa_enabled, mfa_secret"

func (d *Database) GetUser(username string) (*User, error) {
	row := d.db.QueryRow("SELECT "+userColumns+" FROM users WHERE username = ?", username)
	return d.scanUser(row)
}

// GetFirstUser returns the lowest-id user row (used for unauthenticated HTTP API dispatch).
func (d *Database) GetFirstUser() (*User, error) {
	row := d.db.QueryRow("SELECT " + userColumns + " FROM users ORDER BY id ASC LIMIT 1")
	return d.scanUser(row)
}

func (d *Database) GetAllUsers() ([]*User, error) {
	rows, err := d.db.Query("SELECT " + userColumns + " FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u, err := d.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// CreateUser inserts a new user (non-admin, non-mod, non-reseller). expiryDays <= 0 means lifetime (expire=0).
// Bypass and API flags are set at creation; omit false,false,false,false for a plain account.
func (d *Database) CreateUser(username, passwordHash, createdBy, theme string, maxTime, concurrents int, vip bool, expiryDays int,
	bypassPowersaving, bypassBlacklist, bypassSoftMaxtime, apiAccess bool) error {
	now := time.Now().Unix()
	var expire int64
	if expiryDays <= 0 {
		expire = 0
	} else {
		expire = now + int64(expiryDays)*86400
	}
	_, err := d.db.Exec(
		"INSERT INTO users (username, password, vip, reseller, `mod`, admin, bypass_powersaving, bypass_blacklist, bypass_softmaxtime, api_access, theme, max_time, concurrents, banned, locked, time_created, created_by, expire, must_change_password, mfa_enabled, mfa_secret) VALUES (?, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, 1, 0, '')",
		username, passwordHash, boolToInt(vip),
		boolToInt(bypassPowersaving), boolToInt(bypassBlacklist), boolToInt(bypassSoftMaxtime), boolToInt(apiAccess),
		theme, maxTime, concurrents, now, createdBy, expire,
	)
	return err
}

func (d *Database) execRowsAffected(query string, args ...interface{}) error {
	res, err := d.db.Exec(query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (d *Database) CountAdmins() (int, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users WHERE admin = 1").Scan(&n)
	return n, err
}

func (d *Database) DeleteUser(username string) error {
	return d.execRowsAffected("DELETE FROM users WHERE username = ?", username)
}

func (d *Database) UpdatePassword(username, newHash string) error {
	return d.execRowsAffected("UPDATE users SET password = ?, must_change_password = 0 WHERE username = ?", newHash, username)
}

func (d *Database) SetBanned(username string, banned bool) error {
	return d.execRowsAffected("UPDATE users SET banned = ? WHERE username = ?", boolToInt(banned), username)
}

func (d *Database) SetLocked(username string, locked bool) error {
	return d.execRowsAffected("UPDATE users SET locked = ? WHERE username = ?", boolToInt(locked), username)
}

// SetRole updates a role column. Column name is whitelisted — never pass user input as role.
func (d *Database) SetRole(username, role string, value bool) error {
	validRoles := map[string]string{
		"vip":       "vip",
		"reseller":  "reseller",
		"admin":     "admin",
		"mod":       "`mod`",
	}
	col, ok := validRoles[role]
	if !ok {
		return fmt.Errorf("invalid role: %s", role)
	}
	query := fmt.Sprintf("UPDATE users SET %s = ? WHERE username = ?", col)
	return d.execRowsAffected(query, boolToInt(value), username)
}

func (d *Database) SetMaxTime(username string, maxTime int) error {
	return d.execRowsAffected("UPDATE users SET max_time = ? WHERE username = ?", maxTime, username)
}

func (d *Database) SetConcurrents(username string, conc int) error {
	return d.execRowsAffected("UPDATE users SET concurrents = ? WHERE username = ?", conc, username)
}

func (d *Database) SetTheme(username, theme string) error {
	return d.execRowsAffected("UPDATE users SET theme = ? WHERE username = ?", theme, username)
}

func (d *Database) SetExpire(username string, expire int64) error {
	return d.execRowsAffected("UPDATE users SET expire = ? WHERE username = ?", expire, username)
}

func (d *Database) SetBypassPowersaving(username string, v bool) error {
	return d.execRowsAffected("UPDATE users SET bypass_powersaving = ? WHERE username = ?", boolToInt(v), username)
}

func (d *Database) SetBypassBlacklist(username string, v bool) error {
	return d.execRowsAffected("UPDATE users SET bypass_blacklist = ? WHERE username = ?", boolToInt(v), username)
}

func (d *Database) SetBypassSoftmaxtime(username string, v bool) error {
	return d.execRowsAffected("UPDATE users SET bypass_softmaxtime = ? WHERE username = ?", boolToInt(v), username)
}

func (d *Database) SetAPIAccess(username string, v bool) error {
	return d.execRowsAffected("UPDATE users SET api_access = ? WHERE username = ?", boolToInt(v), username)
}

func (d *Database) SetMFAEnabled(username string, v bool) error {
	return d.execRowsAffected("UPDATE users SET mfa_enabled = ? WHERE username = ?", boolToInt(v), username)
}

// SetUserMFASecret sets the base32 TOTP secret; empty clears enrollment (user must scan again when MFA is required).
func (d *Database) SetUserMFASecret(username, secret string) error {
	return d.execRowsAffected("UPDATE users SET mfa_secret = ? WHERE username = ?", secret, username)
}

// ExtendAllUsersExpiryDays adds days (as seconds) to every non-lifetime account.
// expire=0 is unchanged. Expired accounts get now+N days; active get expire+N days.
func (d *Database) ExtendAllUsersExpiryDays(days int) (int64, error) {
	if days <= 0 {
		return 0, fmt.Errorf("days must be positive")
	}
	sec := int64(days) * 86400
	res, err := d.db.Exec(`
UPDATE users SET expire = CASE
  WHEN expire = 0 THEN 0
  WHEN expire < UNIX_TIMESTAMP() THEN UNIX_TIMESTAMP() + ?
  ELSE expire + ?
END`, sec, sec)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *Database) RenameUser(oldName, newName string) error {
	res, err := d.db.Exec("UPDATE users SET username = ? WHERE username = ?", newName, oldName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetExpiryDaysFromNow sets expire to now+days*86400, or 0 if days<=0 (no expiry / lifetime).
func (d *Database) SetExpiryDaysFromNow(username string, days int) error {
	var expire int64
	if days <= 0 {
		expire = 0
	} else {
		expire = time.Now().Unix() + int64(days)*86400
	}
	return d.SetExpire(username, expire)
}

// ExtendExpiryByDays adds days to max(now, current expire). If expire was 0 or in the past, counts from now.
func (d *Database) ExtendExpiryByDays(username string, days int) error {
	if days <= 0 {
		return fmt.Errorf("days must be positive")
	}
	u, err := d.GetUser(username)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	base := u.Expire
	if u.Expire == 0 || u.Expire < now {
		base = now
	}
	return d.SetExpire(username, base+int64(days)*86400)
}

func (d *Database) GetGroupOngoingCount(methods []string) (int, error) {
	if len(methods) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(methods))
	args := make([]interface{}, len(methods))
	for i, m := range methods {
		placeholders[i] = "?"
		args[i] = m
	}
	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM logs WHERE method IN (%s) AND time_sent + duration > UNIX_TIMESTAMP()",
		strings.Join(placeholders, ","),
	)
	var count int
	err := d.db.QueryRow(query, args...).Scan(&count)
	return count, err
}

// LogAttack inserts the attack row first (before outbound dispatch) so ongoing counts and SSH/API views
// stay correct across CNC restarts. Returns new row id and time_sent (unix seconds).
func (d *Database) LogAttack(username, host string, port, duration int, method string) (logID int64, timeSent int64, err error) {
	timeSent = time.Now().Unix()
	res, err := d.db.Exec(
		"INSERT INTO logs (username, host, port, duration, method, time_sent) VALUES (?, ?, ?, ?, ?, ?)",
		username, host, port, duration, method, timeSent,
	)
	if err != nil {
		return 0, 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, timeSent, err
	}
	return id, timeSent, nil
}

func (d *Database) GetUserAttackCount(username string) (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM logs WHERE username = ?", username).Scan(&count)
	return count, err
}

func (d *Database) GetOngoingAttacks() ([]AttackLog, error) {
	rows, err := d.db.Query(
		"SELECT id, username, host, port, duration, method, time_sent FROM logs WHERE time_sent + duration > UNIX_TIMESTAMP() ORDER BY time_sent DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []AttackLog
	for rows.Next() {
		var a AttackLog
		if err := rows.Scan(&a.ID, &a.Username, &a.Host, &a.Port, &a.Duration, &a.Method, &a.TimeSent); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}
	return attacks, nil
}

func (d *Database) GetOngoingCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM logs WHERE time_sent + duration > UNIX_TIMESTAMP()").Scan(&count)
	return count, err
}

func (d *Database) GetUserOngoingCount(username string) (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM logs WHERE username = ? AND time_sent + duration > UNIX_TIMESTAMP()", username).Scan(&count)
	return count, err
}

func (d *Database) GetMethodOngoingCount(method string) (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM logs WHERE method = ? AND time_sent + duration > UNIX_TIMESTAMP()", method).Scan(&count)
	return count, err
}

func (d *Database) GetRecentAttacks(username string, limit int) ([]AttackLog, error) {
	rows, err := d.db.Query(
		"SELECT id, username, host, port, duration, method, time_sent FROM logs WHERE username = ? ORDER BY time_sent DESC LIMIT ?",
		username, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []AttackLog
	for rows.Next() {
		var a AttackLog
		if err := rows.Scan(&a.ID, &a.Username, &a.Host, &a.Port, &a.Duration, &a.Method, &a.TimeSent); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}
	return attacks, nil
}

func (d *Database) GetSpamCount(username string, seconds int) (int, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM logs WHERE username = ? AND time_sent > UNIX_TIMESTAMP() - ?",
		username, seconds,
	).Scan(&count)
	return count, err
}

func (d *Database) GetTargetSpamCount(username, host string, seconds int) (int, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM logs WHERE username = ? AND host = ? AND time_sent > UNIX_TIMESTAMP() - ?",
		username, host, seconds,
	).Scan(&count)
	return count, err
}
