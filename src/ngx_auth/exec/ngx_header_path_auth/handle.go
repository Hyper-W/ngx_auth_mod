package main

import (
	"encoding/binary"
	"fmt"
	"net/http"

	"ngx_auth/etag"
)

func get_path_right(rpath string, user string) bool {
	pathid, ok := check_path(rpath)
	if !ok {
		return UserMap.Authz(NomatchRight, user)
	}

	right_type, has := PathRight[pathid]
	if !has {
		return UserMap.Authz(DefaultRight, user)
	}

	return UserMap.Authz(right_type, user)
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

func set_int64bin(bin []byte, v int64) {
	binary.LittleEndian.PutUint64(bin, uint64(v))
}

func makeEtag(ms int64, user, rpath string) string {
	pathid, ok := check_path(rpath)
	if ok {
		pathid = "M" + pathid
	} else {
		pathid = "N"
	}

	tm := make([]byte, 8)
	set_int64bin(tm, ms)

	return etag.Make(tm, etag.Crypt(tm, []byte(user)), []byte(pathid))
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

	user := r.Header.Get(UserHeader)
	if user == "" {
		HttpResponse.Nouser.Error(w)
		return
	}

	if NegCacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", NegCacheSeconds))
	}

	tag := makeEtag(StartTimeMS, user, rpath)
	w.Header().Set("Etag", tag)
	if UseEtag {
		if !isModified(r.Header, tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	if !get_path_right(rpath, user) {
		HttpResponse.Forbidden.Error(w)
		return
	}

	if CacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", CacheSeconds))
	}
	w.Header().Set("Etag", tag)
	HttpResponse.Ok.Error(w)
}
