package ldap_auth

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"regexp"
	"strings"
	"time"
	"unicode"

	logger "ngx_auth/logger"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	LogLevelMinimum = iota
	LogLevelNormal
	LogLevelMaximum
)

type Config struct {
	HostUrl        string
	StartTls       bool
	SkipCertVerify bool
	RootCaFiles    []string

	BaseDn       string
	BindDn       string
	UniqueFilter string
	AuthzFilter  string

	Timeout int
}

type LdapAuth struct {
	cfg  *Config
	conn *ldap.Conn
}

var paramReg = regexp.MustCompile(`%[a-z%]`)

const hex_ascii = "0123456789abcdef"
const dn_escape_chars = ",=\n+<>#;\\\""

func escape_dn(str string) string {
	var b strings.Builder
	for _, r := range str {
		switch {
		case unicode.IsControl(r):
			bin := []byte(string([]rune{r}))
			for _, c := range bin {
				b.Write([]byte{'\\', hex_ascii[c>>4], hex_ascii[c&0x0f]})
			}
		case strings.ContainsRune(dn_escape_chars, r):
			b.Write([]byte{'\\'})
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

func replace_user(val_fmt string, user string) string {
	esc_user := escape_dn(user)
	return paramReg.ReplaceAllStringFunc(val_fmt, func(m string) string {
		switch m {
		case "%s":
			return esc_user
		case "%%":
			return "%"
		}
		return ""
	})
}

// logIfLevel logs the message only if the current level >= requiredLevel
func logIfLevel(requiredLevel int, format string, v ...interface{}) {
	if logger.GetLoggingLevel() >= requiredLevel {
		logger.LogWithTime(format, v...)
	}
}

func NewLdapAuth(cfg *Config) (*LdapAuth, error) {

	ca_pool := x509.NewCertPool()
	if len(cfg.RootCaFiles) > 0 {
		for _, fn := range cfg.RootCaFiles {
			ca_pem, e := ioutil.ReadFile(fn)
			if e != nil {
				logger.LogWithTime("LDAP CA file read error: file=%s err=%v", fn, e)
				return nil, e
			}
			ca_pool.AppendCertsFromPEM(ca_pem)
		}
	} else {
		var e error
		ca_pool, e = x509.SystemCertPool()
		if e != nil {
			logger.LogWithTime("LDAP system cert pool error: err=%v", e)
			return nil, e
		}
	}

	tls_cfg := &tls.Config{
		InsecureSkipVerify: cfg.SkipCertVerify,
		RootCAs:            ca_pool,
	}

	l, lerr := ldap.DialURL(cfg.HostUrl, ldap.DialWithTLSConfig(tls_cfg))
	if lerr != nil {
		logger.LogWithTime("LDAP dial error: host=%s err=%v", cfg.HostUrl, lerr)
		return nil, lerr
	}

	if cfg.StartTls {
		e := l.StartTLS(tls_cfg)
		if e != nil {
			logger.LogWithTime("LDAP StartTLS error: host=%s err=%v", cfg.HostUrl, e)
			return nil, e
		}
	}
	tout := cfg.Timeout
	if tout <= 0 {
		tout = 1000
	}

	l.SetTimeout(time.Duration(tout) * time.Millisecond)

	return &LdapAuth{cfg: cfg, conn: l}, nil
}
func (lba *LdapAuth) Close() {
	if lba.conn != nil {
		lba.conn.Close()
	}
}

func (lba *LdapAuth) new_search_param(flt_pat string, user string) *ldap.SearchRequest {
	filter := replace_user(flt_pat, ldap.EscapeFilter(user))
	return ldap.NewSearchRequest(
		lba.cfg.BaseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		lba.cfg.Timeout,
		false,
		filter,
		[]string{"dn"},
		nil)
}

func (lba *LdapAuth) Authenticate(user, pass, clientIP string) (bool, bool, error) {
	bind_dn := replace_user(lba.cfg.BindDn, user)
	if err := lba.conn.Bind(bind_dn, pass); err != nil {
		// Bind failures are always logged (minimum level)
		logger.LogWithTime("LDAP bind failed: bind_dn=%s user=%s client_ip=%s err=%v", bind_dn, user, clientIP, err)
		return false, false, nil
	}

	// Bind success is logged at normal level
	logIfLevel(LogLevelNormal, "LDAP bind succeeded: bind_dn=%s user=%s client_ip=%s", bind_dn, user, clientIP)

	if lba.cfg.UniqueFilter != "" {
		res, e := lba.conn.Search(lba.new_search_param(lba.cfg.UniqueFilter, user))
		if e != nil {
			// Filter errors are always logged
			logger.LogWithTime("LDAP unique filter search error: user=%s filter=%s client_ip=%s err=%v", user, lba.cfg.UniqueFilter, clientIP, e)
			return false, false, e
		}
		if len(res.Entries) != 1 {
			// Filter mismatches are always logged
			logger.LogWithTime("LDAP unique filter no match: user=%s filter=%s client_ip=%s entries=%d", user, lba.cfg.UniqueFilter, clientIP, len(res.Entries))
			return false, false, nil
		}
		// Unique filter success is logged at maximum level
		logIfLevel(LogLevelMaximum, "LDAP unique filter succeeded: user=%s filter=%s client_ip=%s", user, lba.cfg.UniqueFilter, clientIP)
	}
	if lba.cfg.AuthzFilter != "" {
		res, e := lba.conn.Search(lba.new_search_param(lba.cfg.AuthzFilter, user))
		if e != nil {
			// Filter errors are always logged
			logger.LogWithTime("LDAP authz filter search error: user=%s filter=%s client_ip=%s err=%v", user, lba.cfg.AuthzFilter, clientIP, e)
			return true, false, e
		}
		if len(res.Entries) != 1 {
			// Filter mismatches are always logged
			logger.LogWithTime("LDAP authz filter no match: user=%s filter=%s client_ip=%s entries=%d", user, lba.cfg.AuthzFilter, clientIP, len(res.Entries))
			return true, false, nil
		}
		// Authz filter success is logged at maximum level
		logIfLevel(LogLevelMaximum, "LDAP authz filter succeeded: user=%s filter=%s client_ip=%s", user, lba.cfg.AuthzFilter, clientIP)
	}

	return true, true, nil
}
