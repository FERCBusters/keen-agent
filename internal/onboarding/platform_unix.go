//go:build linux || darwin

package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

func elevated() bool { return os.Geteuid() == 0 }
func configRoot() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/KEEN/Posture"
	}
	return "/etc/keen-workstation"
}
func configPath() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(configRoot(), "config.json")
	}
	return filepath.Join(configRoot(), "config.yaml")
}
func trusted(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return errors.New("untrusted installation path")
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
func privateDir(path string) error {
	if e := trusted(filepath.Dir(path)); e != nil {
		return e
	}
	if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e := trusted(path); e != nil {
		return e
	}
	s, e := os.Lstat(path)
	if e != nil || !s.IsDir() {
		return errors.New("not a directory")
	}
	return os.Chmod(path, 0700)
}
func prepare() error {
	if runtime.GOOS == "darwin" {
		if e := privateDir("/Library/Application Support/KEEN"); e != nil {
			return e
		}
	}
	if e := privateDir(configRoot()); e != nil {
		return e
	}
	if runtime.GOOS == "darwin" {
		return privateDir(filepath.Join(configRoot(), "state"))
	}
	u, e := user.Lookup("keen-agent")
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown(configRoot(), 0, gid); e != nil {
		return e
	}
	return os.Chmod(configRoot(), 0750)
}
func protectFile(path string) error {
	if runtime.GOOS == "darwin" {
		return os.Chmod(path, 0600)
	}
	u, e := user.Lookup("keen-agent")
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown(path, 0, gid); e != nil {
		return e
	}
	return os.Chmod(path, 0640)
}
func configBytes(r Request) []byte {
	if runtime.GOOS == "darwin" {
		b, _ := json.Marshal(map[string]any{"endpoint": r.URL, "token_file": filepath.Join(configRoot(), "token"), "state_dir": filepath.Join(configRoot(), "state"), "interval_seconds": 3600})
		return b
	}
	// JSON string escaping is also valid YAML scalar escaping.
	u, _ := json.Marshal(r.URL)
	return []byte("endpoint: " + string(u) + "\ntoken_file: /etc/keen-workstation/token\nstate_dir: /var/lib/keen-workstation\nqueue_mb: 32\npoll_seconds: 15\ninitial_lookback: 2h\nsources:\n  - name: workstation-posture\n    kind: journal\n    parser: posture\n")
}
func run(ctx context.Context, p string, args ...string) error {
	if e := trusted(p); e != nil {
		return e
	}
	c := exec.CommandContext(ctx, p, args...)
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"}
	return c.Run()
}
func activate(ctx context.Context) error {
	if runtime.GOOS == "darwin" {
		if e := trusted("/usr/local/libexec/keen-posture"); e != nil {
			return e
		}
		if e := trusted("/Library/LaunchDaemons/net.keen.posture.plist"); e != nil {
			return e
		}
		if e := run(ctx, "/bin/launchctl", "enable", "system/net.keen.posture"); e != nil {
			return e
		}
		if e := run(ctx, "/bin/launchctl", "print", "system/net.keen.posture"); e != nil {
			if e = run(ctx, "/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons/net.keen.posture.plist"); e != nil {
				return e
			}
		}
		return run(ctx, "/bin/launchctl", "kickstart", "system/net.keen.posture")
	}
	if e := run(ctx, "/usr/bin/systemctl", "daemon-reload"); e != nil {
		return e
	}
	if e := run(ctx, "/usr/bin/systemctl", "enable", "--now", "keen-workstation.service", "keen-posture-host.timer"); e != nil {
		return e
	}
	return run(ctx, "/usr/bin/systemctl", "start", "keen-posture-host.service")
}

// Open only a regular file without following a final symlink or blocking on a FIFO.
func OpenRequest(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute request path required")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("regular request file required")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	parent, pe := os.Lstat(filepath.Dir(path))
	if !ok || st.Uid == 0 || st.Nlink != 1 || s.Mode().Perm()&0077 != 0 || pe != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("private user request required")
	}
	pst, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || pst.Uid != st.Uid {
		f.Close()
		return nil, errors.New("request directory owner mismatch")
	}
	return f, nil
}
