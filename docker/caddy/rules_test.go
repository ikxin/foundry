package caddystatic

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func provisionRules(t *testing.T, headers, redirects string, files map[string]string) *StaticRules {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{"_headers": headers, "_redirects": redirects}
	for name, content := range files {
		all[name] = content
	}
	for name, content := range all {
		filename := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := &StaticRules{Root: root}
	if err := s.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	return s
}

func requestRules(t *testing.T, s *StaticRules, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Etag", `"original"`)
		w.Header().Set("Cache-Control", "original")
		w.Header().Set("X-Default", "default")
		if r.URL.Path == "/not-found" {
			return caddyhttp.Error(404, os.ErrNotExist)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return nil
		}
		_, err := fmt.Fprint(w, "NEXT "+r.URL.Path)
		return err
	})
	if err := s.ServeHTTP(w, r, next); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestHeaders(t *testing.T) {
	cases := []struct {
		name, rules, target string
		want                map[string]string
	}{
		{"global", "/*\n X-Test: global", "https://site.test/a/b?query=1", map[string]string{"X-Test": "global"}},
		{"overlapping rules merge", "/*\n X-Test: all\n/a/*\n x-test: section\n/a/b\n X-Other: exact", "https://site.test/a/b", map[string]string{"X-Test": "all, section", "X-Other": "exact"}},
		{"strict case", "/About\n X-Test: wrong", "https://site.test/about", map[string]string{"X-Test": ""}},
		{"strict trailing slash", "/about\n X-Test: wrong", "https://site.test/about/", map[string]string{"X-Test": ""}},
		{"wildcard requires slash", "/assets/*\n X-Test: wrong", "https://site.test/assets", map[string]string{"X-Test": ""}},
		{"repeated path", "/a\n X-Test: first\n/a\n X-Test: second\n X-Other: kept", "https://site.test/a", map[string]string{"X-Test": "first, second", "X-Other": "kept"}},
		{"repeated header", "/a\n cache-control: no-cache\n Cache-Control: no-store", "https://site.test/a", map[string]string{"Cache-Control": "no-cache, no-store"}},
		{"override generated headers", "/a\n Etag: custom\n Cache-Control: max-age=10", "https://site.test/a", map[string]string{"Etag": "custom", "Cache-Control": "max-age=10"}},
		{"remove generated headers", "/*\n ! Etag\n ! X-Default", "https://site.test/a", map[string]string{"Etag": "", "X-Default": ""}},
		{"remove broad header", "/*\n X-Test: global\n/*.jpg\n ! X-Test", "https://site.test/a.jpg", map[string]string{"X-Test": ""}},
		{"replace after removal", "/*\n X-Test: global\n/a\n ! X-Test\n X-Test: exact", "https://site.test/a", map[string]string{"X-Test": "exact"}},
		{"splat capture", "/a/*\n X-Test: :splat", "https://site.test/a/b/c", map[string]string{"X-Test": "b/c"}},
		{"named capture", "/movies/:title\n X-Test: watching :title", "https://site.test/movies/test", map[string]string{"X-Test": "watching test"}},
		{"host captures ignore protocol port", "https://:version.:project.pages.dev/*\n X-Test: :version.:project/:splat", "http://v1.test.pages.dev:1234/a/b", map[string]string{"X-Test": "v1.test/a/b"}},
		{"host captures exclude dots", "https://:project.pages.dev/*\n X-Test: wrong", "https://v1.test.pages.dev/a", map[string]string{"X-Test": ""}},
		{"hostname capture case", "https://:PROJECT.PAGES.DEV/*\n X-Test: :PROJECT", "https://test.pages.dev/a", map[string]string{"X-Test": "test"}},
		{"Netlify multiple globs", "/assets/*/*.js\n X-Test: matched", "https://site.test/assets/a/app.js", map[string]string{"X-Test": "matched"}},
		{"multiple globs and named capture", "/assets/:group/*/*.js\n X-Test: :group", "https://site.test/assets/main/a/app.js", map[string]string{"X-Test": "main"}},
		{"Cloudflare headers override Netlify exclusions", "/*\n Location: /custom\n Server: custom\n Set-Cookie: name=value", "https://site.test/a", map[string]string{"Location": "/custom", "Server": "custom", "Set-Cookie": "name=value"}},
		{"headers on errors", "/*\n X-Test: error", "https://site.test/not-found", map[string]string{"X-Test": "error"}},
		{"unsupported block does not leak", "/valid\n X-Valid: yes\nftp://unsupported/*\n X-Test: wrong\n/a\n X-Other: valid", "https://site.test/valid", map[string]string{"X-Valid": "yes", "X-Test": "", "X-Other": ""}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := provisionRules(t, test.rules, "", nil)
			w := requestRules(t, s, httptest.NewRequest("GET", test.target, nil))
			for name, expected := range test.want {
				if actual := w.Result().Header.Get(name); actual != expected {
					t.Errorf("%s = %q; want %q", name, actual, expected)
				}
			}
		})
	}
}

func TestRewrites(t *testing.T) {
	s := provisionRules(t, "/a\n X-Original: yes\n/b\n X-Target: must-not-apply", "/a /b 200\n/b /c 200\n/missing /absent 200\n/private /_headers 200\n/encoded /caf%C3%A9.html 200\n/spa/* /index.html 200", map[string]string{"b.html": "B CONTENT", "c.html": "C CONTENT", "café.html": "UNICODE", "index.html": "SPA", "spa/existing.html": "ORIGINAL"})
	w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test/a", nil))
	if w.Code != 200 || w.Body.String() != "B CONTENT" || w.Header().Get("Location") != "" || w.Header().Get("X-Original") != "yes" || w.Header().Get("X-Target") != "" {
		t.Fatalf("rewrite response: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	etag := w.Header().Get("Etag")
	for _, test := range []struct {
		method, target, header, value, body string
		status                              int
	}{
		{"HEAD", "/a", "", "", "", 200},
		{"GET", "/a", "Range", "bytes=0-0", "B", 206},
		{"GET", "/a", "If-None-Match", etag, "", 304},
		{"GET", "/missing", "", "", "404 page not found\n", 404},
		{"GET", "/private", "", "", "404 page not found\n", 404},
		{"GET", "/encoded", "", "", "UNICODE", 200},
		{"GET", "/spa/existing", "", "", "SPA", 200},
	} {
		r := httptest.NewRequest(test.method, "https://site.test"+test.target, nil)
		if test.header != "" {
			r.Header.Set(test.header, test.value)
		}
		w := requestRules(t, s, r)
		if w.Code != test.status || w.Body.String() != test.body {
			t.Errorf("%s %s: got %d %q; want %d %q", test.method, test.target, w.Code, w.Body.String(), test.status, test.body)
		}
	}
	for _, status := range []int{401, 404, 410, 451} {
		s := provisionRules(t, "", fmt.Sprintf("/gone /closed.html %d!", status), map[string]string{"closed.html": "CLOSED"})
		r := httptest.NewRequest("GET", "https://site.test/gone", nil)
		r.Header.Set("Range", "bytes=0-0")
		r.Header.Set("If-None-Match", "*")
		w := requestRules(t, s, r)
		if w.Code != status || w.Body.String() != "CLOSED" {
			t.Errorf("custom error: got %d %q; want %d CLOSED", w.Code, w.Body.String(), status)
		}
	}
}

func TestNetlifyConditions(t *testing.T) {
	s := provisionRules(t, "", "/country /cn 302 Country=cn,tw\n/lang /zh 302 Language=zh\n/cookie /preview 302 Cookie=preview,other\n/chain /israel 302 Country=il\n/israel /israel/he 302 Language=he", nil)
	s.CountryHeader = "CF-IPCountry"
	for _, test := range []struct {
		target, name, value, location string
		trusted                       bool
	}{
		{"/country", "Cookie", "nf_country=CN", "/cn", false},
		{"/country", "CF-IPCountry", "TW", "/cn", true},
		{"/country", "CF-IPCountry", "TW", "", false},
		{"/country", "Cookie", "nf_country=US", "", false},
		{"/lang", "Accept-Language", "zh-TW;q=0.1,en;q=1", "/zh", false},
		{"/lang", "Cookie", "nf_lang=zh-CN", "/zh", false},
		{"/lang", "Accept-Language", "en,zh;q=0.9", "", false},
		{"/cookie", "Cookie", "PreVIEW=", "/preview", false},
		{"/cookie", "Cookie", "OTHER=1", "/preview", false},
		{"/cookie", "Cookie", "unrelated=preview", "", false},
	} {
		r := httptest.NewRequest("GET", "https://site.test"+test.target, nil)
		r.Header.Set(test.name, test.value)
		if test.trusted {
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.TrustedProxyVarKey: true}))
		}
		w := requestRules(t, s, r)
		if w.Header().Get("Location") != test.location {
			t.Errorf("%s %s: got %q, want %q", test.target, test.value, w.Header().Get("Location"), test.location)
		}
	}
	r := httptest.NewRequest("GET", "https://site.test/chain", nil)
	r.Header.Set("Cookie", "nf_country=il")
	r.Header.Set("Accept-Language", "he")
	if w := requestRules(t, s, r); w.Header().Get("Location") != "/israel" {
		t.Fatalf("conditional redirect did not stop at the first match: %v", w.Header())
	}
}

func TestNetlifyAuthentication(t *testing.T) {
	s := provisionRules(t, "/protected/*\n Basic-Auth: alice:password bob:other", "/admin/* /admin/:splat 200! Role=admin", map[string]string{"admin/index.html": "ADMIN"})
	s.JWTSecret = "test-secret"
	for _, credentials := range []string{"", "alice:wrong", "alice:password", "bob:other"} {
		r := httptest.NewRequest("GET", "https://site.test/protected/file", nil)
		if user, password, ok := strings.Cut(credentials, ":"); ok {
			r.SetBasicAuth(user, password)
		}
		w := requestRules(t, s, r)
		want := 401
		if credentials == "alice:password" || credentials == "bob:other" {
			want = 200
		}
		if w.Code != want || w.Header().Get("Basic-Auth") != "" {
			t.Errorf("Basic-Auth: got %d %v; want %d with no credentials header", w.Code, w.Header(), want)
		}
	}
	jwt := func(secret, alg string, exp int64) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)))
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"app_metadata":{"authorization":{"roles":["admin"]}}}`, exp)))
		data := header + "." + payload
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(data))
		return data + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	for _, test := range []struct {
		token  string
		status int
	}{
		{"", 404},
		{jwt("wrong-secret", "HS256", time.Now().Add(time.Hour).Unix()), 404},
		{jwt(s.JWTSecret, "none", time.Now().Add(time.Hour).Unix()), 404},
		{jwt(s.JWTSecret, "HS256", time.Now().Add(-time.Hour).Unix()), 404},
		{jwt(s.JWTSecret, "HS256", time.Now().Add(time.Hour).Unix()), 200},
	} {
		r := httptest.NewRequest("GET", "https://site.test/admin/", nil)
		r.AddCookie(&http.Cookie{Name: "nf_jwt", Value: test.token})
		if w := requestRules(t, s, r); w.Code != test.status {
			t.Errorf("Role: got %d %q; want %d", w.Code, w.Body.String(), test.status)
		}
	}
	fallback := provisionRules(t, "", "/admin/* /admin/:splat 200! Role=admin\n/admin/* /login.html 401!", map[string]string{"admin/index.html": "ADMIN", "login.html": "LOGIN"})
	w := requestRules(t, fallback, httptest.NewRequest("GET", "https://site.test/admin/", nil))
	if w.Code != 401 || w.Body.String() != "LOGIN" {
		t.Fatalf("role fallback: %d %q", w.Code, w.Body.String())
	}
	specific := provisionRules(t, "/*\n Basic-Auth: alice:password\n/private/*\n Basic-Auth: bob:other", "", nil)
	r := httptest.NewRequest("GET", "https://site.test/private/page", nil)
	r.SetBasicAuth("bob", "other")
	if w := requestRules(t, specific, r); w.Code != 200 {
		t.Fatal("later Basic-Auth rule did not override the broader rule")
	}
}

func TestNetlifyProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/upstream/a%2Fb?q=1" || r.Method != "POST" || r.Header.Get("X-Forwarded-Host") != "site.test" {
			t.Errorf("unexpected proxy request: %s %s %v", r.Method, r.RequestURI, r.Header)
		}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(201)
		io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	s := provisionRules(t, "/*\n X-Local: must-not-apply", "/api/* "+upstream.URL+"/upstream/:splat 200", nil)
	r := httptest.NewRequest("POST", "https://site.test/api/a%2Fb?q=1", strings.NewReader("BODY"))
	w := requestRules(t, s, r)
	if w.Code != 201 || w.Body.String() != "BODY" || w.Header().Get("X-Local") != "" || w.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("proxy response: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
}

func TestSignedProxyAndAuthentication(t *testing.T) {
	t.Setenv("AUDIT_PROXY_KEY", "proxy-secret")
	t.Setenv("SITE_ID", "site-id")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.Header.Get("X-Nf-Sign"), ".")
		if len(parts) != 3 {
			t.Error("missing proxy signature")
			w.WriteHeader(500)
			return
		}
		mac := hmac.New(sha256.New, []byte("proxy-secret"))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		if json.Unmarshal(payload, &claims) != nil || !hmac.Equal(signature, mac.Sum(nil)) || claims["iss"] != "netlify" || claims["netlify_id"] != "site-id" || claims["exp"].(float64) <= float64(time.Now().Unix()) {
			t.Error("invalid signed proxy claims")
		}
		fmt.Fprint(w, "SIGNED")
	}))
	defer upstream.Close()
	s := provisionRules(t, "/api/*\n Basic-Auth: user:password", "/api/* "+upstream.URL+"/:splat 200 Sign=AUDIT_PROXY_KEY", nil)
	r := httptest.NewRequest("GET", "https://site.test/api/test", nil)
	if w := requestRules(t, s, r); w.Code != 401 {
		t.Fatal("proxy bypassed Basic-Auth")
	}
	r.SetBasicAuth("user", "password")
	if w := requestRules(t, s, r); w.Code != 200 || w.Body.String() != "SIGNED" {
		t.Fatalf("signed proxy failed: %d %q", w.Code, w.Body.String())
	}
	t.Setenv("AUDIT_PROXY_KEY", "")
	w := httptest.NewRecorder()
	err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { t.Error("unexpected fallback"); return nil }))
	if handlerErr, ok := err.(caddyhttp.HandlerError); !ok || handlerErr.StatusCode != 500 {
		t.Fatalf("missing signing secret must fail closed, got %v", err)
	}
}

func TestRewriteFallbackAndEmptyResponse(t *testing.T) {
	s := provisionRules(t, "/*\n X-Test: retained", "/missing /absent 200", map[string]string{"404.html": "CUSTOM NOT FOUND"})
	w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test/missing", nil))
	if w.Code != 404 || w.Body.String() != "CUSTOM NOT FOUND" || w.Header().Get("X-Test") != "retained" {
		t.Fatalf("custom 404 fallback: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	w = httptest.NewRecorder()
	err := s.ServeHTTP(w, httptest.NewRequest("HEAD", "https://site.test/empty", nil), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }))
	if err != nil || w.Result().Header.Get("X-Test") != "retained" || w.Body.Len() != 0 {
		t.Fatalf("empty response lost headers: %v %v", err, w.Header())
	}
}

func TestStreamingHeaders(t *testing.T) {
	s := provisionRules(t, "/*\n Etag: custom\n ! X-Remove\n ! Content-Type\n ! Date\n ! Content-Length", "", nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Etag", "generated")
			w.Header().Set("X-Remove", "generated")
			if r.URL.Path == "/flush" {
				if err := http.NewResponseController(w).Flush(); err != nil {
					return err
				}
			}
			_, err := io.Copy(w, struct{ io.Reader }{strings.NewReader("STREAM")})
			return err
		}))
		if err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for _, target := range []string{"/copy", "/flush"} {
		response, err := http.Get(server.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "STREAM" || response.Header.Get("Etag") != "custom" || response.Header.Get("X-Remove") != "" || response.Header.Get("Date") != "" || response.Header.Get("Content-Type") != "" || response.Header.Get("Content-Length") != "" {
			t.Fatalf("streaming response: %q %v %v", body, response.Header, err)
		}
	}
}

func TestConcurrentCaptures(t *testing.T) {
	s := provisionRules(t, "/view/:id\n X-Capture: :id", "/view/:id /page.html 200\n/go/:id /target/:id?value=:id 302", map[string]string{"page.html": "PAGE"})
	var group sync.WaitGroup
	for i := range 32 {
		group.Go(func() {
			for _, route := range []string{"view", "go"} {
				r := httptest.NewRequest("GET", fmt.Sprintf("https://site.test/%s/%d", route, i), nil)
				w := requestRules(t, s, r)
				if route == "view" && (w.Code != 200 || w.Header().Get("X-Capture") != strconv.Itoa(i)) {
					t.Errorf("concurrent header capture: %d %v", w.Code, w.Header())
				}
				if route == "go" && w.Header().Get("Location") != fmt.Sprintf("/target/%d?value=%d", i, i) {
					t.Errorf("concurrent redirect capture: %v", w.Header())
				}
			}
		})
	}
	group.Wait()
}

func TestUnifiedRulesIgnorePlatformAndSaaSQuotas(t *testing.T) {
	for _, obsolete := range []string{"netlify", "cloudflare", "invalid"} {
		t.Setenv("STATIC_RULES_PLATFORM", obsolete)
		s := provisionRules(t, "", "/a /b", nil)
		if w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test/a", nil)); w.Code != 302 {
			t.Fatal("obsolete platform variable changed unified behavior")
		}
	}
	if err := (&StaticRules{Root: t.TempDir()}).Provision(caddy.Context{}); err != nil {
		t.Fatalf("absent rule files should be optional: %v", err)
	}
	var headers, redirects strings.Builder
	for i := range 101 {
		fmt.Fprintf(&headers, "/header%d\n X-Limit: %d\n", i, i)
	}
	for i := range 2001 {
		fmt.Fprintf(&redirects, "/static%d /destination\n", i)
	}
	for i := range 101 {
		fmt.Fprintf(&redirects, "/dynamic%d/* /destination\n", i)
	}
	fmt.Fprintf(&headers, "/long-header\n X-Long: %s\n", strings.Repeat("x", 2500))
	fmt.Fprintf(&redirects, "%s /unsupported\n", strings.Repeat("x", 1024*1024))
	fmt.Fprintf(&redirects, "/long-redirect /%s\n", strings.Repeat("x", 1500))
	s := provisionRules(t, headers.String(), redirects.String(), nil)
	for _, test := range []struct {
		target string
		status int
		header string
	}{
		{"/static2000", 302, ""}, {"/dynamic100/path", 302, ""}, {"/header100", 200, "100"},
	} {
		w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test"+test.target, nil))
		if w.Code != test.status || w.Header().Get("X-Limit") != test.header {
			t.Errorf("unexpected SaaS quota at %s: %d %v", test.target, w.Code, w.Header())
		}
	}
	if w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test/long-header", nil)); len(w.Header().Get("X-Long")) != 2500 {
		t.Fatal("SaaS line limit truncated a supported header")
	}
	if w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test/long-redirect", nil)); w.Code != 302 {
		t.Fatal("SaaS line limit dropped a supported redirect")
	}
}

func TestRedirects(t *testing.T) {
	cases := []struct {
		name, rules, target, location string
		status                        int
	}{
		{"default 302", "/old /new", "/old?x=1", "/new?x=1", 302},
		{"first duplicate", "/old /first\n/old /last", "/old", "/first", 302},
		{"first file match", "/* /wild\n/old /exact", "/old", "/wild", 302},
		{"strict trailing slash", "/old /new", "/old/", "", 200},
		{"remove slash", "/old/ /old 301", "/old/", "/old", 301},
		{"suffix splat", "/old/* /new/:splat 308", "/old/a/b?x=1", "/new/a/b?x=1", 308},
		{"middle splat", "/old/*.html /new/:splat 307", "/old/a/b.html", "/new/a/b", 307},
		{"named captures", "/:year/:slug /news/:slug?year=:year#:slug", "/2026/story", "/news/story?year=2026#story", 302},
		{"splat query fragment", "/old/* /new?path=:splat#:splat", "/old/a/b", "/new?path=a/b#a/b", 302},
		{"encoded source", "/caf%C3%A9 /new", "/caf%C3%A9", "/new", 302},
		{"unicode source", "/中文 /new", "/%E4%B8%AD%E6%96%87", "/new", 302},
		{"encoded slash capture", "/old/:id /new/:id", "/old/a%2Fb", "/new/a%2Fb", 302},
		{"query replacement", "/old /new?x=2", "/old?x=1&y=3", "/new?x=2", 302},
		{"empty target query inherits", "/old /new?", "/old?x=1", "/new?x=1", 302},
		{"query capture", "/store id=:id /blog/:id 301", "/store?id=my-post", "/blog/my-post", 301},
		{"query literal", "/store id=123 /blog/post", "/store?id=123", "/blog/post", 302},
		{"exact query keys", "/store id=:id /blog/:id", "/store?id=123&extra=1", "", 200},
		{"duplicate query values", "/store id=:id /blog/:id", "/store?id=123&id=456", "", 200},
		{"encoded query capture", "/store id=:id /blog/:id", "/store?id=a%2Fb%3Fc", "/blog/a%2Fb%3Fc", 302},
		{"query capture separators", "/store id=:id /blog?name=:id", "/store?id=a%26b%3Dx%23fragment", "/blog?name=a%26b%3Dx%23fragment", 302},
		{"conditional duplicate fallback", "/store id=:id /blog/:id\n/store /fallback", "/store", "/fallback", 302},
		{"external redirect", "/old https://example.net/new", "/old?x=1", "https://example.net/new?x=1", 302},
		{"external host capture", "/old/:host https://:host.example.net/", "/old/docs", "https://docs.example.net/", 302},
		{"Netlify domain redirect", "https://site.test/old /new 302!", "/old", "/new", 302},
		{"domain wildcard", "https://site.test/* /new/:splat 302!", "/old", "/new/old", 302},
		{"forward shorthand", "/forward/* 200!", "/forward/file", "", 404},
		{"inline comment", "/old /new#fragment 301 # comment", "/old", "/new#fragment", 301},
		{"invalid status ignored", "/old /invalid 999\n/old /new", "/old", "/new", 302},
		{"307 supported", "/old /new 307", "/old", "/new", 307},
		{"force flag accepted", "/old /new 301!", "/old", "/new", 301},
		{"existing file overridden", "/existing /new", "/existing", "/new", 302},
		{"existing file with force", "/existing /new 302!", "/existing", "/new", 302},
		{"slashless wildcard base excluded", "/old/* /new/:splat", "/old", "", 200},
		{"unknown condition ignored as whole rule", "/old /bad 302 Unsupported=true\n/old /new", "/old", "/new", 302},
		{"invalid source ignored", "ftp://site.test/old /bad\n/old /new", "/old", "/new", 302},
		{"invalid destination ignored", "/old javascript:alert(1) 302\n/old /new", "/old", "/new", 302},
		{"unsupported multiple splats ignored", "/old/*/* /bad\n/old/:id/:name /new", "/old/a/b", "/new", 302},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := provisionRules(t, "/*\n X-Must-Not-Leak: value", test.rules, map[string]string{"existing.html": "existing"})
			w := requestRules(t, s, httptest.NewRequest("GET", "https://site.test"+test.target, nil))
			if w.Code != test.status || w.Header().Get("Location") != test.location {
				t.Fatalf("got %d Location=%q; want %d Location=%q", w.Code, w.Header().Get("Location"), test.status, test.location)
			}
			if test.status >= 300 && test.status < 400 && w.Header().Get("X-Must-Not-Leak") != "" {
				t.Fatal("redirect inherited _headers")
			}
		})
	}
}
