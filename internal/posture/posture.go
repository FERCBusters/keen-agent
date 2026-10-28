// Package posture collects bounded, read-only observations, never compliance verdicts.
package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"keen-agent/internal/posturemodel"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MaxOutput = 1024 * 1024

type Observation = posturemodel.Observation

func observation(check, provider, scope string) Observation {
	return posturemodel.New(check, provider, scope)
}

// System is injectable: tests never run host commands or change desktop settings.
type System interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Read(string) ([]byte, error)
	Tail(string) ([]byte, error)
	Glob(string) ([]string, error)
	Env(string) string
	UID() int
	Now() time.Time
}
type Local struct{ Session bool }
type capped struct{ bytes.Buffer }

func (b *capped) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxOutput {
		return 0, errors.New("output limit")
	}
	return b.Buffer.Write(p)
}

var programs = map[string][]string{
	"zfs": {"/usr/sbin/zfs", "/sbin/zfs"}, "dpkg-query": {"/usr/bin/dpkg-query"},
	"lsblk": {"/usr/bin/lsblk", "/bin/lsblk"}, "findmnt": {"/usr/bin/findmnt", "/bin/findmnt"},
	"systemctl": {"/usr/bin/systemctl", "/bin/systemctl"}, "loginctl": {"/usr/bin/loginctl", "/bin/loginctl"},
	"apt-config": {"/usr/bin/apt-config"}, "ufw": {"/usr/sbin/ufw"}, "firewall-cmd": {"/usr/bin/firewall-cmd"},
	"nft": {"/usr/sbin/nft"}, "iptables-save": {"/usr/sbin/iptables-save", "/sbin/iptables-save"}, "ip6tables-save": {"/usr/sbin/ip6tables-save", "/sbin/ip6tables-save"},
	"mdatp": {"/usr/bin/mdatp"}, "sigtool": {"/usr/bin/sigtool"},
	"gsettings": {"/usr/bin/gsettings"}, "xfconf-query": {"/usr/bin/xfconf-query"},
	"kreadconfig6": {"/usr/bin/kreadconfig6"}, "kreadconfig5": {"/usr/bin/kreadconfig5"},
	"busctl": {"/usr/bin/busctl"},
}

// Follow distro binary symlinks only after validating the resolved path and all
// its parents. Never execute a user-supplied PATH entry as root.
func trustedExecutable(path string) (string, error) {
	p, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", e
	}
	info, e := os.Stat(p)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return "", errors.New("not executable")
	}
	for d := p; ; d = filepath.Dir(d) {
		st, e := os.Stat(d)
		if e != nil {
			return "", e
		}
		u, ok := st.Sys().(*syscall.Stat_t)
		if !ok || u.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return "", errors.New("untrusted executable ownership")
		}
		if d == "/" {
			break
		}
	}
	return p, nil
}
func (l Local) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	choices, ok := programs[name]
	if !ok {
		return nil, errors.New("command not allowlisted")
	}
	path := ""
	invocation := ""
	for _, p := range choices {
		if v, e := trustedExecutable(p); e == nil {
			path = v
			invocation = p
			break
		}
	}
	if path == "" {
		return nil, os.ErrNotExist
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := probeCommand(cctx, path, invocation, args...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	if l.Session {
		for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "DCONF_PROFILE"} {
			if v := os.Getenv(k); v != "" {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
	}
	var out capped
	cmd.Stdout = &out
	var stderr capped
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return nil, commandError(name, e, cctx.Err(), stderr.String())
	}
	return out.Bytes(), nil
}
func (Local) Read(path string) ([]byte, error) {
	// Nonblocking prevents FIFOs in user-controlled configuration paths hanging a collector.
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not regular")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxOutput+1))
	if len(b) > MaxOutput {
		return nil, errors.New("file limit")
	}
	return b, e
}

// Tail reads a bounded suffix of known local logs; no compressed logs or scans.
func (Local) Tail(path string) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not regular")
	}
	offset := max(int64(0), st.Size()-128*1024)
	if _, e = f.Seek(offset, io.SeekStart); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, 128*1024))
	if offset > 0 {
		if n := bytes.IndexByte(b, '\n'); n >= 0 {
			b = b[n+1:]
		} else {
			return nil, errors.New("oversized log line")
		}
	}
	return b, e
}
func (Local) Glob(p string) ([]string, error) {
	v, e := filepath.Glob(p)
	if len(v) > 1024 {
		return nil, errors.New("path limit")
	}
	return v, e
}
func (Local) Env(k string) string { return os.Getenv(k) }
func (Local) UID() int            { return os.Getuid() }
func (Local) Now() time.Time      { return time.Now().UTC() }
func query(ctx context.Context, s System, name string, args ...string) (string, error) {
	b, e := s.Run(ctx, name, args...)
	return strings.TrimSpace(string(b)), e
}
func properties(b string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(b, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}
func unit(ctx context.Context, s System, name string) map[string]string {
	b, e := query(ctx, s, "systemctl", "show", name, "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainStatus,ExecMainExitTimestamp,LastTriggerUSec,NextElapseUSecRealtime,DropInPaths,ConditionResult")
	if e != nil {
		return nil
	}
	return properties(b)
}
func yes(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1", "on":
		return true, true
	case "false", "no", "0", "off":
		return false, true
	}
	return false, false
}
func boolFact(o *Observation, key, v string) bool {
	b, ok := yes(v)
	if ok {
		o.Facts[key] = strconv.FormatBool(b)
	}
	return ok
}
func number(v string) (int64, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "uint32 "))
	n, e := strconv.ParseInt(v, 10, 64)
	return n, e == nil && n >= 0 && n <= 31536000
}
func setNumber(o *Observation, k, v string, mult int64) bool {
	n, ok := number(v)
	if ok && n*mult <= 31536000 {
		o.Facts[k] = strconv.FormatInt(n*mult, 10)
		return true
	}
	return false
}
func failed(o Observation, reason string) Observation {
	o.Status = "unknown"
	o.Reason = reason
	return o
}

// Emit writes one JSON line per observation, then the run's coverage line.
func Emit(w io.Writer, observations []Observation, coverage posturemodel.Coverage) error {
	enc := json.NewEncoder(w)
	for _, o := range observations {
		if e := o.Validate(); e != nil {
			return e
		}
		if e := enc.Encode(o); e != nil {
			return e
		}
	}
	if e := coverage.Validate(); e != nil {
		return e
	}
	return enc.Encode(coverage)
}
func Host(ctx context.Context, s System) []Observation {
	var all []Observation
	if IsQubes(s) {
		all = append(all, QubesContext("host"), QubesContext("session"), QubesContext("network"))
	} else {
		all = append(all, Disks(ctx, s)...)
	}
	all = append(all, Firewalls(ctx, s)...)
	all = append(all, Updates(ctx, s)...)
	all = append(all, Antivirus(ctx, s)...)
	all = append(all, Sessions(ctx, s))
	return all
}

// Execute the validated target while preserving argv[0] for xtables multicall.
func probeCommand(ctx context.Context, path, invocation string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = invocation
	return cmd
}
