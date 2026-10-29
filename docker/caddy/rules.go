package caddystatic

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(StaticRules{})
	httpcaddyfile.RegisterHandlerDirective("static_rules", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		s := new(StaticRules)
		for h.Next() {
			if !h.AllArgs(&s.Root) {
				return nil, h.ArgErr()
			}
			for h.NextBlock(0) {
				var value *string
				switch h.Val() {
				case "country_header":
					value = &s.CountryHeader
				case "jwt_secret":
					value = &s.JWTSecret
				default:
					return nil, h.Errf("unknown static_rules option %q", h.Val())
				}
				if !h.AllArgs(value) || h.NextBlock(1) {
					return nil, h.ArgErr()
				}
			}
		}
		return s, nil
	})
	httpcaddyfile.RegisterDirectiveOrder("static_rules", httpcaddyfile.Before, "file_server")
}

// StaticRules combines _headers and _redirects syntax from static hosts,
// preferring Cloudflare semantics wherever the platforms disagree.
type StaticRules struct {
	Root          string `json:"root,omitempty"`
	CountryHeader string `json:"country_header,omitempty"`
	JWTSecret     string `json:"jwt_secret,omitempty"`

	headers   []headerRule
	redirects []redirectRule
}

type rulePattern struct {
	regexp   *regexp.Regexp
	absolute bool
	scheme   string
	header   bool
}

type headerRule struct {
	pattern rulePattern
	set     http.Header
	unset   []string
	users   [][32]byte
}

type redirectRule struct {
	pattern    rulePattern
	target     string
	status     int
	signed     string
	query      map[string]string
	conditions map[string][]string
}

func (StaticRules) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.static_rules", New: func() caddy.Module { return new(StaticRules) }}
}

func (s *StaticRules) Provision(_ caddy.Context) error {
	if s.CountryHeader == "" {
		s.CountryHeader = os.Getenv("STATIC_RULES_COUNTRY_HEADER")
	}
	if s.CountryHeader != "" && !httpguts.ValidHeaderFieldName(s.CountryHeader) {
		return errors.New("invalid static_rules country_header")
	}
	if s.JWTSecret == "" {
		s.JWTSecret = os.Getenv("STATIC_RULES_JWT_SECRET")
	}
	s.headers, s.redirects = nil, nil
	if err := s.readHeaders(); err != nil {
		return err
	}
	return s.readRedirects()
}

// Unsupported declarations are ignored silently. File IO errors remain fatal.
func (s *StaticRules) readRules(name string, parse func(string) error) error {
	filename := path.Join(s.Root, name)
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		raw, err := reader.ReadString('\n')
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		if line != "" && !strings.HasPrefix(line, "#") {
			_ = parse(line)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}
	}
}

func (s *StaticRules) readHeaders() error {
	var current *headerRule
	return s.readRules("_headers", func(line string) error {
		isPath := strings.HasPrefix(line, "/") || strings.Contains(strings.Fields(line)[0], "://")
		if isPath {
			current = nil
			pattern, err := compilePattern(line, true)
			if err != nil {
				return err
			}
			s.headers = append(s.headers, headerRule{pattern: pattern, set: make(http.Header)})
			current = &s.headers[len(s.headers)-1]
			return nil
		}
		if current == nil {
			return errors.New("header must follow a valid URL pattern")
		}
		if strings.HasPrefix(line, "! ") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "! "))
			if !httpguts.ValidHeaderFieldName(name) {
				return errors.New("invalid header removal")
			}
			current.unset = append(current.unset, http.CanonicalHeaderKey(name))
			return nil
		}
		name, value, found := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !found || value == "" || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return errors.New("expected a valid header name and nonempty value")
		}
		if strings.EqualFold(name, "Basic-Auth") {
			var users [][32]byte
			for _, credentials := range strings.Fields(value) {
				if !strings.Contains(credentials, ":") {
					return errors.New("Basic-Auth credentials must contain username:password")
				}
				users = append(users, sha256.Sum256([]byte(credentials)))
			}
			current.users = append(current.users, users...)
			return nil
		}
		current.set.Add(name, value)
		return nil
	})
}

func (s *StaticRules) readRedirects() error {
	return s.readRules("_redirects", func(line string) error {
		fields := strings.Fields(line)
		for i, token := range fields {
			if strings.HasPrefix(token, "#") {
				fields = fields[:i]
				break
			}
		}
		if len(fields) < 2 {
			return errors.New("expected source destination [status] [conditions]")
		}
		rule := redirectRule{status: http.StatusFound, query: make(map[string]string), conditions: make(map[string][]string)}
		source := fields[0]
		if code, err := strconv.Atoi(strings.TrimSuffix(fields[1], "!")); err == nil {
			if code != 200 || !strings.HasSuffix(source, "/*") {
				return errors.New("omitted destinations require a /* forward rule with status 200")
			}
			fields = append([]string{source, strings.TrimSuffix(source, "*") + ":splat"}, fields[1:]...)
		}
		pattern, err := compilePattern(source, false)
		if err != nil {
			return err
		}
		rule.pattern = pattern
		i := 1
		for i < len(fields) && strings.Contains(fields[i], "=") && !isTarget(fields[i]) {
			key, value, _ := strings.Cut(fields[i], "=")
			if key == "" {
				return errors.New("empty query parameter name")
			}
			rule.query[key] = value
			i++
		}
		if i >= len(fields) || !isTarget(fields[i]) {
			return errors.New("destination must be a path or HTTP(S) URL")
		}
		rule.target = fields[i]
		i++
		if i < len(fields) && !strings.Contains(fields[i], "=") {
			// All rules already override files; Netlify's ! suffix is redundant.
			rule.status, err = strconv.Atoi(strings.TrimSuffix(fields[i], "!"))
			if err != nil {
				return errors.New("invalid redirect status")
			}
			i++
		}
		for ; i < len(fields); i++ {
			key, value, found := strings.Cut(fields[i], "=")
			key = strings.ToLower(key)
			if !found || value == "" {
				return errors.New("invalid redirect condition")
			}
			switch key {
			case "country", "language", "role", "cookie":
				rule.conditions[key] = strings.Split(value, ",")
			case "sign", "signed":
				rule.signed = value
			default:
				return fmt.Errorf("unknown redirect condition %q", key)
			}
		}
		if !validStatus(rule.status) {
			return errors.New("unsupported redirect status")
		}
		if _, err := parseTarget(rule.target); err != nil {
			return err
		}
		if rule.signed != "" && (rule.status != 200 || strings.HasPrefix(rule.target, "/")) {
			return errors.New("signed rules require an external 200 proxy destination")
		}
		s.redirects = append(s.redirects, rule)
		return nil
	})
}

func isTarget(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://")
}

func validStatus(status int) bool {
	return status == 200 || (status >= 300 && status <= 599)
}

// Match escaped paths: %2F stays in one segment and captures aren't decoded twice.
func compilePattern(source string, header bool) (rulePattern, error) {
	pattern := rulePattern{header: header}
	if strings.ContainsAny(source, " \t\r\n") {
		return pattern, errors.New("URL patterns cannot contain whitespace")
	}
	if scheme, rest, found := strings.Cut(source, "://"); found {
		if (scheme != "http" && scheme != "https") || (header && scheme != "https") {
			return pattern, errors.New("absolute URL pattern is not supported here")
		}
		host, suffix, _ := strings.Cut(rest, "/")
		if host == "" || strings.Contains(host, "@") {
			return pattern, errors.New("invalid pattern hostname")
		}
		if header && portSuffix.MatchString(host) {
			return pattern, errors.New("Cloudflare header patterns cannot specify a port")
		}
		pattern.absolute, pattern.scheme = true, scheme
		source = host + "/" + suffix
	} else if !strings.HasPrefix(source, "/") {
		return pattern, errors.New("URL pattern must begin with /")
	}
	source, _, _ = strings.Cut(source, "?")
	source, _, _ = strings.Cut(source, "#")
	wildcards := strings.Count(source, "*")
	if !header && wildcards > 1 {
		return pattern, errors.New("only one wildcard is allowed")
	}
	source = escapeUnicodePath(source)
	var expression strings.Builder
	expression.WriteByte('^')
	if pattern.absolute {
		expression.WriteString("(?i:")
	}
	names := make(map[string]bool)
	inHost := pattern.absolute
	for i := 0; i < len(source); {
		if source[i] == '/' && inHost {
			expression.WriteByte(')')
			inHost = false
		}
		if source[i] == '*' {
			if header && wildcards > 1 {
				expression.WriteString(".*")
				i++
				continue
			}
			if names["splat"] {
				return pattern, errors.New("duplicate splat capture")
			}
			names["splat"] = true
			expression.WriteString("(?P<splat>.*)")
			i++
			continue
		}
		if source[i] == ':' && i+1 < len(source) && asciiLetter(source[i+1]) {
			j := i + 2
			for j < len(source) && (asciiLetter(source[j]) || source[j] >= '0' && source[j] <= '9' || source[j] == '_') {
				j++
			}
			name := source[i+1 : j]
			if names[name] {
				return pattern, errors.New("duplicate placeholder name")
			}
			names[name] = true
			expression.WriteString("(?P<" + name + ">")
			if inHost {
				expression.WriteString("[^/.]+)")
			} else {
				expression.WriteString("[^/]+)")
			}
			i = j
			continue
		}
		expression.WriteString(regexp.QuoteMeta(source[i : i+1]))
		i++
	}
	expression.WriteByte('$')
	compiled, err := regexp.Compile(expression.String())
	pattern.regexp = compiled
	return pattern, err
}

func asciiLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }

func escapeUnicodePath(value string) string {
	var result strings.Builder
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 128 || strings.ContainsRune("\"<>`{}", rune(b)) {
			result.WriteByte('%')
			result.WriteByte(hex[b>>4])
			result.WriteByte(hex[b&15])
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

func (pattern rulePattern) match(r *http.Request) (map[string]string, bool) {
	value := r.URL.EscapedPath()
	if value == "" {
		value = "/"
	}
	if pattern.absolute {
		host := r.Host
		if pattern.header {
			host = (&url.URL{Host: host}).Hostname()
		} else if requestScheme(r) != pattern.scheme {
			return nil, false
		}
		value = strings.ToLower(host) + value
	}
	match := pattern.regexp.FindStringSubmatch(value)
	if match == nil {
		return nil, false
	}
	values := make(map[string]string)
	for i, name := range pattern.regexp.SubexpNames() {
		if name != "" {
			values[name] = match[i]
		}
	}
	return values, true
}

func requestScheme(r *http.Request) string {
	if caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey) == true {
		if scheme := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); scheme == "http" || scheme == "https" {
			return scheme
		}
	}
	if r.TLS != nil || r.URL.Scheme == "https" {
		return "https"
	}
	return "http"
}

var (
	placeholder = regexp.MustCompile(`:([A-Za-z]\w*)`)
	portSuffix  = regexp.MustCompile(`:\d+$`)
)

func expand(value string, captures map[string]string) string {
	return placeholder.ReplaceAllStringFunc(value, func(token string) string {
		if replacement, exists := captures[token[1:]]; exists {
			return replacement
		}
		return token
	})
}

func parseTarget(target string) (*url.URL, error) {
	// A host placeholder would otherwise be mistaken for a port by url.Parse.
	validation := placeholder.ReplaceAllString(target, "capture")
	u, err := url.Parse(validation)
	if err != nil || !isTarget(target) || u.User != nil || (u.IsAbs() && (u.Host == "" || u.Scheme != "http" && u.Scheme != "https")) {
		return nil, errors.New("invalid redirect destination")
	}
	return u, nil
}

func (rule redirectRule) location(r *http.Request, captures map[string]string) (*url.URL, error) {
	target := expand(rule.target, captures)
	// A captured leading slash must not turn a relative path into an external URL.
	if strings.HasPrefix(rule.target, "/") {
		target = "/" + strings.TrimLeft(target, "/")
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || (u.IsAbs() && (u.Host == "" || u.Scheme != "http" && u.Scheme != "https")) {
		return nil, errors.New("invalid expanded redirect destination")
	}
	if u.RawQuery == "" && len(rule.query) == 0 {
		u.RawQuery, u.ForceQuery = r.URL.RawQuery, r.URL.ForceQuery
	}
	return u, nil
}

func (s *StaticRules) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if privatePath(r.URL.Path) {
		http.NotFound(w, r)
		return nil
	}
	if !s.authorized(r) {
		writer := s.headerWriter(w, r)
		writer.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	rule, target, denied := s.matchRedirect(r)
	if rule != nil {
		if rule.status >= 300 && rule.status <= 399 {
			location := target.String()
			if target.Host == r.Host && target.Scheme == requestScheme(r) {
				copy := *target
				copy.Scheme, copy.Host = "", ""
				location = copy.String()
			}
			s.vary(w.Header())
			w.Header().Set("Location", location)
			w.WriteHeader(rule.status)
			return nil
		}
		if target.IsAbs() {
			return s.proxy(w, r, target, rule)
		}
		s.serveRewrite(s.headerWriter(w, r), r, target, rule.status)
		return nil
	}
	writer := s.headerWriter(w, r)
	if denied {
		http.NotFound(writer, r)
		return nil
	}
	err := next.ServeHTTP(writer, r)
	var handlerError caddyhttp.HandlerError
	if errors.As(err, &handlerError) && handlerError.StatusCode >= 400 && handlerError.StatusCode < 500 && !writer.wroteHeader {
		http.Error(writer, http.StatusText(handlerError.StatusCode), handlerError.StatusCode)
		return nil
	}
	if err == nil && !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	return err
}

func (s *StaticRules) matchRedirect(r *http.Request) (*redirectRule, *url.URL, bool) {
	denied := false
	for i := range s.redirects {
		rule := &s.redirects[i]
		captures, match := rule.pattern.match(r)
		if !match || !rule.matchQuery(r, captures) || !s.matchConditions(rule, r) {
			continue
		}
		if roles := rule.conditions["role"]; len(roles) > 0 && !hasAny(s.roles(r), roles, false) {
			denied = true
			continue
		}
		target, err := rule.location(r, captures)
		if err != nil {
			continue
		}
		return rule, target, false
	}
	return nil, nil, denied
}

func (rule redirectRule) matchQuery(r *http.Request, captures map[string]string) bool {
	if len(rule.query) == 0 {
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != len(rule.query) {
		return false
	}
	for key, expected := range rule.query {
		values, exists := query[key]
		if !exists || len(values) != 1 {
			return false
		}
		if placeholder.FindString(expected) == expected && expected != "" {
			// Captures may be reused in either a path or a query string. Encode
			// separators as well, so a captured '&' cannot create another parameter.
			captures[expected[1:]] = strings.ReplaceAll(url.QueryEscape(values[0]), "+", "%20")
		} else if values[0] != expected {
			return false
		}
	}
	return true
}

func (s *StaticRules) matchConditions(rule *redirectRule, r *http.Request) bool {
	for name, expected := range rule.conditions {
		switch name {
		case "country":
			value := cookieValue(r, "nf_country")
			if value == "" && s.CountryHeader != "" && caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey) == true {
				value = r.Header.Get(s.CountryHeader)
			}
			if !hasAny([]string{value}, expected, true) {
				return false
			}
		case "language":
			language := cookieValue(r, "nf_lang")
			if language == "" {
				language = strings.TrimSpace(strings.Split(strings.Split(r.Header.Get("Accept-Language"), ",")[0], ";")[0])
			}
			found := false
			for _, candidate := range expected {
				found = found || strings.EqualFold(language, candidate) || strings.HasPrefix(strings.ToLower(language), strings.ToLower(candidate)+"-")
			}
			if !found {
				return false
			}
		case "cookie":
			found := false
			for _, cookie := range r.Cookies() {
				found = found || hasAny([]string{cookie.Name}, expected, true)
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func cookieValue(r *http.Request, name string) string {
	if cookie, err := r.Cookie(name); err == nil {
		return cookie.Value
	}
	return ""
}

func hasAny(actual, expected []string, fold bool) bool {
	for _, a := range actual {
		for _, b := range expected {
			if a == b || fold && strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

func (s *StaticRules) roles(r *http.Request) []string {
	token := cookieValue(r, "nf_jwt")
	if s.JWTSecret == "" || len(token) > 16384 {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	var algorithm struct{ Alg, Typ string }
	if err != nil || json.Unmarshal(header, &algorithm) != nil || algorithm.Alg != "HS256" || algorithm.Typ != "JWT" {
		return nil
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	mac := hmac.New(sha256.New, []byte(s.JWTSecret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Exp         int64 `json:"exp"`
		Nbf         int64 `json:"nbf"`
		AppMetadata struct {
			Roles         []string `json:"roles"`
			Authorization struct {
				Roles []string `json:"roles"`
			} `json:"authorization"`
		} `json:"app_metadata"`
	}
	now := time.Now().Unix()
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Exp <= now || claims.Nbf > now {
		return nil
	}
	return append(claims.AppMetadata.Roles, claims.AppMetadata.Authorization.Roles...)
}

func (s *StaticRules) vary(headers http.Header) {
	for _, rule := range s.redirects {
		for name := range rule.conditions {
			switch name {
			case "country":
				addVary(headers, "Cookie")
				if s.CountryHeader != "" {
					addVary(headers, s.CountryHeader)
				}
			case "language":
				addVary(headers, "Cookie")
				addVary(headers, "Accept-Language")
			case "cookie", "role":
				addVary(headers, "Cookie")
			}
		}
	}
}

func addVary(headers http.Header, name string) {
	for _, value := range headers.Values("Vary") {
		for _, existing := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(existing), name) || existing == "*" {
				return
			}
		}
	}
	headers.Add("Vary", name)
}

type headerOperations struct {
	set   http.Header
	unset []string
}

func (s *StaticRules) authorized(r *http.Request) bool {
	var users [][32]byte
	for _, rule := range s.headers {
		if len(rule.users) == 0 {
			continue
		}
		if _, matches := rule.pattern.match(r); !matches {
			continue
		}
		users = rule.users
	}
	if len(users) == 0 {
		return true
	}
	username, password, provided := r.BasicAuth()
	digest := sha256.Sum256([]byte(username + ":" + password))
	authorized := 0
	for _, user := range users {
		authorized |= subtle.ConstantTimeCompare(user[:], digest[:])
	}
	return provided && authorized != 0
}

func (s *StaticRules) headerWriter(w http.ResponseWriter, r *http.Request) *ruleResponseWriter {
	var operations []headerOperations
	for _, rule := range s.headers {
		captures, matches := rule.pattern.match(r)
		if !matches {
			continue
		}
		set := make(http.Header)
		for name, values := range rule.set {
			value := expand(strings.Join(values, ", "), captures)
			if httpguts.ValidHeaderFieldValue(value) {
				set.Set(name, value)
			}
		}
		operations = append(operations, headerOperations{set: set, unset: rule.unset})
	}
	s.vary(w.Header())
	return &ruleResponseWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, operations: operations}
}

type ruleResponseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	operations  []headerOperations
	wroteHeader bool
	status      int
}

func (w *ruleResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	if status >= 100 && status <= 199 {
		w.ResponseWriterWrapper.WriteHeader(status)
		return
	}
	w.wroteHeader = true
	if w.status != 0 && status >= 200 && status < 300 {
		status = w.status
	}
	set := make(map[string]bool)
	for _, operation := range w.operations {
		for _, name := range operation.unset {
			w.Header().Del(name)
			// net/http otherwise recreates these transport defaults at send time.
			if name == "Content-Type" || name == "Content-Length" || name == "Date" {
				w.Header()[name] = nil
			}
		}
		for name, values := range operation.set {
			value := strings.Join(values, ", ")
			if set[name] && w.Header().Get(name) != "" {
				value = w.Header().Get(name) + ", " + value
			}
			w.Header().Set(name, value)
			set[name] = true
		}
	}
	w.ResponseWriterWrapper.WriteHeader(status)
}

func (w *ruleResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.Write(data)
}

func (w *ruleResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.ReadFrom(reader)
}

func (w *ruleResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriterWrapper).Flush()
}

func privatePath(value string) bool {
	for _, segment := range strings.Split(path.Clean(value), "/") {
		switch segment {
		case ".git", "node_modules", "vendor", ".venv", "_headers", "_redirects":
			return true
		}
	}
	return false
}

// Resolve actual files, extensionless HTML documents, and directory indexes.
func (s *StaticRules) asset(requestPath string) (string, error) {
	if privatePath(requestPath) {
		return "", os.ErrNotExist
	}
	for _, candidate := range []string{requestPath, strings.TrimRight(requestPath, "/") + ".html", path.Join(requestPath, "index.html")} {
		filename := caddyhttp.SanitizedPathJoin(s.Root, candidate)
		info, err := os.Stat(filename)
		if err == nil && info.Mode().IsRegular() {
			return filename, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrInvalid) {
			return "", err
		}
	}
	return "", os.ErrNotExist
}

func (s *StaticRules) serveRewrite(w *ruleResponseWriter, r *http.Request, target *url.URL, status int) {
	filename, err := s.asset(target.Path)
	if err != nil {
		filename, err = s.asset("/404.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		status = http.StatusNotFound
	}
	file, err := os.Open(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	request := r.Clone(r.Context())
	request.URL = target
	if status != 200 {
		w.status = status
		for _, name := range []string{"Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			request.Header.Del(name)
		}
	}
	w.Header().Set("Etag", fmt.Sprintf(`"%x-%x"`, info.ModTime().UnixNano(), info.Size()))
	http.ServeContent(w, request, info.Name(), info.ModTime(), file)
}

func (s *StaticRules) proxy(w http.ResponseWriter, r *http.Request, target *url.URL, rule *redirectRule) error {
	var signature string
	if rule.signed != "" {
		secret := os.Getenv(rule.signed)
		if secret == "" {
			return caddyhttp.Error(http.StatusInternalServerError, errors.New("proxy signing environment variable is not set"))
		}
		claims := map[string]any{
			"iss": "netlify", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
			"deploy_context": os.Getenv("CONTEXT"), "netlify_id": os.Getenv("SITE_ID"), "site_url": os.Getenv("URL"),
		}
		if claims["deploy_context"] == "" {
			claims["deploy_context"] = "production"
		}
		if claims["site_url"] == "" {
			claims["site_url"] = requestScheme(r) + "://" + r.Host
		}
		payload, _ := json.Marshal(claims)
		data := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(data))
		signature = data + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	// Netlify does not apply _headers to externally proxied content.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			copy := *target
			copy.Fragment = ""
			request.Out.URL = &copy
			request.Out.Host = target.Host
			request.SetXForwarded()
			if signature != "" {
				request.Out.Header.Set("X-Nf-Sign", signature)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, http.StatusText(status), status)
		},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 26*time.Second)
	defer cancel()
	if rule.status >= 400 {
		w = &ruleResponseWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, status: rule.status}
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
	return nil
}

var (
	_ caddy.Provisioner           = (*StaticRules)(nil)
	_ caddyhttp.MiddlewareHandler = (*StaticRules)(nil)
)
