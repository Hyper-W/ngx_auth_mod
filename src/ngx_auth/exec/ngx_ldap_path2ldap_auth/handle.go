package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"

	"github.com/l4go/var_mtx"

	"ngx_auth/etag"
	"ngx_auth/ldap_auth"
	"ngx_auth/logger"
)

func get_path_filter(rpath string) (bool, string) {
	pathid, ok := check_path(rpath)
	if !ok {
		if BanNomatch {
			return false, ""
		}
		return true, NomatchFilter
	}

	filter, has := PathFilter[pathid]
	if has {
		return true, filter
	}
	if BanDefault {
		return false, ""
	}
	return true, DefaultFilter
}

func check_path(rpath string) (string, bool) {
	if PathPatternReg == nil {
		return "", false
	}
	matchs := PathPatternReg.FindStringSubmatch(rpath)
	if len(matchs) < 1 {
		return "", false
	}

	return matchs[1], true
}

func http_not_auth(w http.ResponseWriter, _ *http.Request) {
	realm := strings.Replace(AuthRealm, `"`, `\"`, -1)
	w.Header().Add("WWW-Authenticate", `Basic realm="`+realm+`"`)

	HttpResponse.Unauth.Error(w)
}

var userMtx = var_mtx.NewVarMutex()

func auth_path(user string, pass string, path string, clientIP string) (bool, bool) {
	ldap_cfg := *LdapAuthConfig
	ok_path, path_filter := get_path_filter(path)
	if !ok_path {
		path_filter = ""
	}

	if UseSerializedAuth {
		userMtx.Lock(user)
		defer userMtx.Unlock(user)
	}

	ldap_cfg.AuthzFilter = path_filter
	la, lerr := ldap_auth.NewLdapAuth(&ldap_cfg)
	if lerr != nil {
		return false, false
	}
	defer la.Close()

	ok_auth, ok_authz, err := la.Authenticate(user, pass, clientIP)
	if err != nil {
		return false, false
	}
	if !ok_path {
		ok_authz = false
	}

	return ok_auth, ok_authz
}

func set_int64bin(bin []byte, v int64) {
	binary.LittleEndian.PutUint64(bin, uint64(v))
}

func makeEtag(ms int64, user, pass, rpath string) string {
	pathid, ok := check_path(rpath)
	if ok {
		pathid = "M" + pathid
	} else {
		pathid = "N"
	}

	tm := make([]byte, 8)
	set_int64bin(tm, ms)

	return etag.Make(tm, etag.Crypt(tm, []byte(user)),
		etag.Hmac([]byte(user), []byte(pass)), []byte(pathid))
}

func isModified(hd http.Header, org_tag string) bool {
	if_nmatch := hd.Get("If-None-Match")

	if if_nmatch != "" {
		return !isEtagMatch(if_nmatch, org_tag)
	}

	return true
}

func isEtagMatch(tag_str string, org_tag string) bool {
	tags, _ := etag.Split(tag_str)
	for _, tag := range tags {
		if tag == org_tag {
			return true
		}
	}

	return false
}

func TestAuthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	rpath := r.Header.Get(PathHeader)
	if rpath == "" {
		HttpResponse.Nopath.Error(w)
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		http_not_auth(w, r)
		return
	}

	// Extract client IP, accounting for proxies (X-Forwarded-For, X-Real-IP)
	clientIP := logger.ExtractClientIP(r)

	if NegCacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", NegCacheSeconds))
	}

	tag := makeEtag(StartTimeMS, user, pass, rpath)
	w.Header().Set("Etag", tag)
	if UseEtag {
		if !isModified(r.Header, tag) {
			w.Header().Set("Etag", tag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	ok_auth, ok_authz := auth_path(user, pass, rpath, clientIP)
	if !ok_auth {
		http_not_auth(w, r)
		return
	}
	if !ok_authz {
		HttpResponse.Forbidden.Error(w)
		return
	}

	if CacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", CacheSeconds))
	}
	HttpResponse.Ok.Error(w)
}
