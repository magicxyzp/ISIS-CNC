package core

import (
	"crypto/rand"
	"strings"

	"github.com/pquerna/otp/totp"
)

// RunMFALogin runs TOTP enrollment or verification after SSH password auth. Returns false to drop the connection.
func (sess *Session) RunMFALogin() bool {
	cfg := sess.config
	if cfg == nil || !cfg.MFARequiredForUser(sess.user) {
		return true
	}

	u, err := sess.db.GetUser(sess.user.Username)
	if err != nil {
		sess.Writeln("\033[97mAccount lookup failed.\033[0;97m")
		return false
	}
	sess.user = u

	secret := strings.TrimSpace(u.MFASecret)
	if secret == "" {
		return sess.enrollTOTP()
	}
	return sess.verifyTOTP(secret)
}

// trimIssuerRunes shortens the TOTP issuer so the otpauth URL fits a smaller QR matrix.
func trimIssuerRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max])
}

func (sess *Session) writeMFACodePrompt() {
	prompt := "Authenticator code: "
	if sess.config != nil {
		prompt = sess.config.MFACodePrompt()
	}
	sess.Write("\033[0;97m" + prompt + "\033[0m")
}

func (sess *Session) mfaWriteEnrollPreamble() {
	if sess.config != nil {
		if sub := sess.config.Settings.MFA.SanitizedMFAEnrollBanner(); sub != "" {
			body := sess.RenderBanner(sub, nil)
			if strings.TrimSpace(body) != "" {
				sess.WriteRenderedTermFX(body, 0, false)
				sess.Writeln("")
				return
			}
		}
	}
	sess.Writeln("")
	sess.Writeln("\033[97mTwo-factor authentication (Google Authenticator) is required.\033[0;97m")
	sess.Writeln("\033[97mScan the QR below in this terminal (UTF-8 + monospace). In PuTTY: Window → Translation → UTF-8.\033[0;97m")
	sess.Writeln("")
}

func (sess *Session) mfaWriteVerifyPreamble() {
	if sess.config != nil {
		if sub := sess.config.Settings.MFA.SanitizedMFAVerifyBanner(); sub != "" {
			body := sess.RenderBanner(sub, nil)
			if strings.TrimSpace(body) != "" {
				sess.WriteRenderedTermFX(body, 0, false)
				sess.Writeln("")
				return
			}
		}
	}
	sess.Writeln("")
	sess.Writeln("\033[97mEnter the 6-digit code from Google Authenticator.\033[0;97m")
	sess.Writeln("")
}

func (sess *Session) enrollTOTP() bool {
	issuer := trimIssuerRunes(sess.config.MFAIssuer(), 24)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: sess.user.Username,
		SecretSize:  20,
		Rand:        rand.Reader,
	})
	if err != nil {
		sess.Writeln("\033[97mMFA setup failed (generate).\033[0;97m")
		return false
	}
	secret := key.Secret()
	url := key.URL()

	sess.mfaWriteEnrollPreamble()

	termQR, err := formatMFAQRForTerminal(url)
	if err != nil {
		sess.Writeln("\033[97mCould not build terminal QR; use the manual entry key below.\033[0;97m")
	} else {
		sess.Write(termQR)
		sess.Writeln("")
	}

	sess.Writeln("")
	sess.Writeln("\033[97mThen enter the 6-digit code here.\033[0;97m")
	sess.Writeln("")
	sess.Writeln("\033[97mManual entry key: " + secret + "\033[0;97m")
	sess.Writeln("")

	for range 5 {
		sess.writeMFACodePrompt()
		line, err := sess.ReadLine()
		if err != nil {
			return false
		}
		code := strings.TrimSpace(strings.ReplaceAll(line, " ", ""))
		if !totp.Validate(code, secret) {
			sess.Writeln("\033[97mInvalid code. Try again.\033[0;97m")
			continue
		}
		if err := sess.db.SetUserMFASecret(sess.user.Username, secret); err != nil {
			sess.Writeln("\033[97mCould not save MFA. Try again later.\033[0;97m")
			return false
		}
		sess.user.MFASecret = secret
		sess.Writeln("\033[97m[+] Authenticator linked.\033[0;97m")
		sess.Writeln("")
		return true
	}
	sess.Writeln("\033[97mToo many failures. Disconnecting.\033[0;97m")
	return false
}

func (sess *Session) verifyTOTP(secret string) bool {
	sess.mfaWriteVerifyPreamble()
	for range 5 {
		sess.writeMFACodePrompt()
		line, err := sess.ReadLine()
		if err != nil {
			return false
		}
		code := strings.TrimSpace(strings.ReplaceAll(line, " ", ""))
		if totp.Validate(code, secret) {
			sess.Writeln("")
			return true
		}
		sess.Writeln("\033[97mInvalid code.\033[0;97m")
	}
	sess.Writeln("\033[97mToo many failures. Disconnecting.\033[0;97m")
	return false
}
