package main

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Source struct {
	ExcludeMatch                string        `yaml:"exclude_match"`
	IncludeWhen                 []FieldFilter `yaml:"include_when"`
	ExcludeWhen                 []FieldFilter `yaml:"exclude_when"`
	Name                        string        `yaml:"name"`
	Kind                        string        `yaml:"kind"`
	Paths                       []string      `yaml:"paths"`
	Units                       []string      `yaml:"units"`
	Parser                      string        `yaml:"parser"`
	Include                     string        `yaml:"include"`
	Exclude                     string        `yaml:"exclude"`
	Multiline                   string        `yaml:"multiline_start"`
	include, exclude, multiline *regexp.Regexp
}
type Config struct {
	Endpoint        string   `yaml:"endpoint"`
	TokenFile       string   `yaml:"token_file"`
	CAFile          string   `yaml:"ca_file"`
	StateDir        string   `yaml:"state_dir"`
	QueueMB         int64    `yaml:"queue_mb"`
	PollSeconds     int      `yaml:"poll_seconds"`
	RetentionDays   int      `yaml:"retention_days"`
	InitialLookback string   `yaml:"initial_lookback"`
	Redact          []string `yaml:"redact"`
	Sources         []Source `yaml:"sources"`
	redactors       []*regexp.Regexp
	lookback        time.Duration
}

func config(path string) (Config, error) {
	c := Config{StateDir: "/var/lib/keen-agent", QueueMB: 256, PollSeconds: 5, InitialLookback: "24h"}
	b, e := readPrivate(path, 1024*1024, false)
	if e != nil {
		return c, e
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("only one YAML document allowed")
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("endpoint must be an HTTPS URL without credentials/query/fragment")
	}
	if !strings.HasSuffix(u.Path, "/v1/otlp/logs") {
		return c, errors.New("endpoint path must end in /v1/otlp/logs")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.TokenFile) {
		return c, errors.New("state_dir and token_file must be absolute")
	}
	if c.QueueMB < 1 || c.QueueMB > 4096 || c.PollSeconds < 1 || c.PollSeconds > 300 || c.RetentionDays < 0 || c.RetentionDays > 365 {
		return c, errors.New("invalid queue, polling or retention limit")
	}
	c.lookback, e = time.ParseDuration(c.InitialLookback)
	if e != nil || c.lookback < 0 || c.lookback > 365*24*time.Hour {
		return c, errors.New("invalid initial_lookback")
	}
	if len(c.Sources) == 0 || len(c.Sources) > 64 {
		return c, errors.New("configure 1 to 64 sources")
	}
	names := map[string]bool{}
	for i := range c.Sources {
		s := &c.Sources[i]
		if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`).MatchString(s.Name) || names[s.Name] {
			return c, errors.New("source names must be unique safe identifiers")
		}
		names[s.Name] = true
		if s.ExcludeMatch != "" && s.ExcludeMatch != "any" && s.ExcludeMatch != "all" {
			return c, errors.New("exclude_match must be any (OR) or all (AND)")
		}
		if err := validateFilters(s.IncludeWhen); err != nil {
			return c, err
		}
		if err := validateFilters(s.ExcludeWhen); err != nil {
			return c, err
		}
		if s.Kind != "file" && s.Kind != "journal" {
			return c, errors.New("source kind must be file or journal")
		}
		switch s.Parser {
		case "raw", "json", "syslog", "nginx", "php", "dpkg", "apt", "dnf", "auditd", "ossec":
		default:
			return c, fmt.Errorf("unknown parser for %s", s.Name)
		}
		if s.Kind == "file" && (len(s.Paths) == 0 || len(s.Paths) > 16) {
			return c, errors.New("file source requires 1 to 16 paths")
		}
		for _, p := range s.Paths {
			if !allowedLogPath(s.Parser, p) {
				return c, errors.New("file paths must be under /var/log (OSSEC alerts also allow /var/ossec/logs/alerts)")
			}
		}
		for _, u := range s.Units {
			if !regexp.MustCompile(`^[a-zA-Z0-9_.@:-]+$`).MatchString(u) {
				return c, errors.New("invalid journal unit")
			}
		}
		for _, pair := range []struct {
			input  string
			target **regexp.Regexp
		}{{s.Include, &s.include}, {s.Exclude, &s.exclude}, {s.Multiline, &s.multiline}} {
			input, target := pair.input, pair.target
			if len(input) > 2048 {
				return c, errors.New("source patterns are limited to 2048 bytes")
			}
			if input != "" {
				*target, e = regexp.Compile(input)
				if e != nil {
					return c, e
				}
			}
		}
	}
	if len(c.Redact) > 32 {
		return c, errors.New("at most 32 custom redaction patterns are allowed")
	}
	for _, pattern := range append([]string{`(?i)"(?:password|passwd|secret|token|access_token|api_key|authorization)"\s*:\s*"[^"\r\n]*"`, `(?i)(authorization|cookie|set-cookie):[^\r\n]+`, `(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`, `(?i)(password|passwd|secret|token|api[_-]?key)[=: ]+["']?[^\s"'&,;]+`}, c.Redact...) {
		if pattern == "" || len(pattern) > 2048 {
			return c, errors.New("redaction patterns must contain 1 to 2048 bytes")
		}
		r, e := regexp.Compile(pattern)
		if e != nil {
			return c, e
		}
		c.redactors = append(c.redactors, r)
	}
	return c, nil
}
func readPrivate(path string, max int64, secret bool) ([]byte, error) {
	f, e := openReadFile(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || (secret && st.Mode().Perm()&0007 != 0) {
		return nil, errors.New("config/credential must be regular, non-writable by group/others; credentials must not be world-readable")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, e
}
func (c Config) redact(s string) string {
	for _, r := range c.redactors {
		s = r.ReplaceAllString(s, "[REDACTED]")
		if len(s) > maxRecord {
			return s[:maxRecord+1]
		}
	}
	return strings.ToValidUTF8(s, "�")
}

// Walk each directory without following symlinks; path resolution remains bound
// to opened directory descriptors even if a directory is concurrently renamed.
func openReadFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("read path must be absolute")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OSSEC gets one narrow additional log root, never its configuration/key directory.
func allowedLogPath(parser, path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, "/var/log/") || (parser == "ossec" && strings.HasPrefix(clean, "/var/ossec/logs/alerts/"))
}

// OSSEC's active alerts.json can be a symlink to its dated log. Resolve only
// this leaf, keep the target beneath the same alert directory, then perform
// the existing descriptor-based no-symlink walk. Other sources are unchanged.
func openLogFile(source Source, path string) (*os.File, error) {
	file, err := openReadFile(path)
	if err == nil || source.Parser != "ossec" || filepath.Base(path) != "alerts.json" {
		return file, err
	}
	target, linkErr := os.Readlink(path)
	if linkErr != nil {
		return nil, err
	}
	root := filepath.Dir(filepath.Clean(path))
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	target = filepath.Clean(target)
	if !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return nil, errors.New("OSSEC alert symlink target leaves alert directory")
	}
	return openReadFile(target)
}
