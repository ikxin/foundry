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

// StaticRules loads exact-path rules from the site's _headers and _redirects files.
type StaticRules struct {
	Root string `json:"root,omitempty"`

	headers   map[string]http.Header
	redirects map[string]redirect
}

type redirect struct {
	target string
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
		if len(fields) != 3 || !strings.HasPrefix(fields[0], "/") {
			return errors.New("expected /source target status")
		}
		target, err := url.ParseRequestURI(fields[1])
		if err != nil || (!strings.HasPrefix(fields[1], "/") &&
			((target.Scheme != "http" && target.Scheme != "https") || target.Host == "")) {
			return fmt.Errorf("invalid redirect target: %q", fields[1])
		}
		status, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("invalid redirect status: %q", fields[2])
		}
		switch status {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return fmt.Errorf("unsupported redirect status: %d", status)
		}
		s.redirects[rulePath(fields[0])] = redirect{target: fields[1], status: status}
		return nil
	})
}

func (s *StaticRules) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	path := rulePath(r.URL.Path)
	if rule, ok := s.redirects[path]; ok {
		http.Redirect(w, r, rule.target, rule.status)
		return nil
	}
	for name, values := range s.headers[path] {
		for _, value := range values {
			w.Header().Set(name, value)
		}
	}
	return next.ServeHTTP(w, r)
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
