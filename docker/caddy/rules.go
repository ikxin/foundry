package caddystatic

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(StaticRules{})
	httpcaddyfile.RegisterHandlerDirective("static_rules", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		rules := new(StaticRules)
		for h.Next() {
			if !h.AllArgs(&rules.Root) {
				return nil, h.ArgErr()
			}
			if h.NextBlock(0) {
				return nil, h.Err("static_rules does not accept a block")
			}
		}
		return rules, nil
	})
	httpcaddyfile.RegisterDirectiveOrder("static_rules", httpcaddyfile.Before, "file_server")
}

// StaticRules loads rules from the site's _headers and _redirects files.
type StaticRules struct {
	Root string `json:"root,omitempty"`

	headers   map[string]http.Header
	redirects map[string]redirect
	wildcards []redirect
}

type redirect struct {
	source string
	target *url.URL
	status int
}

func (StaticRules) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.static_rules",
		New: func() caddy.Module { return new(StaticRules) },
	}
}

func (s *StaticRules) Provision(_ caddy.Context) error {
	s.headers = make(map[string]http.Header)
	s.redirects = make(map[string]redirect)
	s.wildcards = nil
	var headers http.Header

	err := readRules(filepath.Join(s.Root, "_headers"), func(line string) error {
		if strings.HasPrefix(line, "/") {
			headers = make(http.Header)
			s.headers[rulePath(line)] = headers
			return nil
		}
		if headers == nil {
			return errors.New("header must follow a path beginning with /")
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("invalid header: %q", line)
		}
		headers.Set(name, value)
		return nil
	})
	if err != nil {
		return err
	}

	return readRules(filepath.Join(s.Root, "_redirects"), func(line string) error {
		fields := strings.Fields(line)
		if (len(fields) != 2 && len(fields) != 3) || !strings.HasPrefix(fields[0], "/") {
			return errors.New("expected /source target [status]")
		}
		source := strings.TrimRight(fields[0], "/")
		if strings.Contains(source, "*") &&
			(!strings.HasSuffix(source, "/*") || strings.Count(source, "*") != 1) {
			return errors.New("only a trailing /* wildcard is supported")
		}
		target, err := url.Parse(fields[1])
		if err != nil || (!strings.HasPrefix(fields[1], "/") &&
			((target.Scheme != "http" && target.Scheme != "https") || target.Host == "")) {
			return fmt.Errorf("invalid redirect target: %q", fields[1])
		}
		status := http.StatusFound
		if len(fields) == 3 {
			status, err = strconv.Atoi(fields[2])
			if err != nil {
				return fmt.Errorf("invalid redirect status: %q", fields[2])
			}
		}
		switch status {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return fmt.Errorf("unsupported redirect status: %d", status)
		}
		rule := redirect{source: source, target: target, status: status}
		if !strings.HasSuffix(source, "/*") {
			s.redirects[rulePath(source)] = rule
			return nil
		}
		for i, previous := range s.wildcards {
			if previous.source == source {
				s.wildcards[i] = rule
				return nil
			}
		}
		s.wildcards = append(s.wildcards, rule)
		return nil
	})
}

func (s *StaticRules) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	path := rulePath(r.URL.Path)
	if rule, ok := s.redirects[path]; ok {
		target, _ := rule.location(r.URL)
		http.Redirect(w, r, target, rule.status)
		return nil
	}
	for _, rule := range s.wildcards {
		if target, ok := rule.location(r.URL); ok {
			http.Redirect(w, r, target, rule.status)
			return nil
		}
	}
	for name, values := range s.headers[path] {
		for _, value := range values {
			w.Header().Set(name, value)
		}
	}
	return next.ServeHTTP(w, r)
}

func (rule redirect) location(request *url.URL) (string, bool) {
	target := *rule.target
	if strings.HasSuffix(rule.source, "/*") {
		prefix := strings.TrimSuffix(rule.source, "*")
		var splat, escapedSplat string
		switch {
		case request.Path == strings.TrimSuffix(prefix, "/"):
		case strings.HasPrefix(request.Path, prefix):
			splat = strings.TrimPrefix(request.Path, prefix)
			escapedSplat = escapedPathSuffix(request, len(prefix))
		default:
			return "", false
		}
		escapedTarget := target.EscapedPath()
		target.Path = strings.ReplaceAll(target.Path, ":splat", splat)
		target.RawPath = strings.ReplaceAll(escapedTarget, ":splat", escapedSplat)
		if target.Host == "" && strings.HasPrefix(target.Path, "//") {
			target.RawPath = "/%2F" + target.EscapedPath()[2:]
		}
	} else if rule.source != strings.TrimRight(request.Path, "/") {
		return "", false
	}
	if target.RawQuery == "" && !target.ForceQuery {
		target.RawQuery = request.RawQuery
		target.ForceQuery = request.ForceQuery
	}
	return target.String(), true
}

// Skip decoded prefix bytes without unescaping the captured redirect path.
func escapedPathSuffix(u *url.URL, prefixLength int) string {
	path := u.EscapedPath()
	for range prefixLength {
		if path[0] == '%' {
			path = path[3:]
		} else {
			path = path[1:]
		}
	}
	return path
}

func rulePath(path string) string {
	return strings.TrimRight(path, "/") + "/"
}

// Missing rule files are optional; malformed or unreadable files stop startup.
func readRules(filename string, parse func(string) error) error {
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := parse(line); err != nil {
			return fmt.Errorf("%s:%d: %w", filename, lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", filename, err)
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*StaticRules)(nil)
	_ caddyhttp.MiddlewareHandler = (*StaticRules)(nil)
)
