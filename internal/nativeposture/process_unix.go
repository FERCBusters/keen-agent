//go:build !windows

package nativeposture

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func prepareCommand(c *exec.Cmd) {
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=/var/root"}
	c.Dir = "/"
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		if c.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
}

func trustedExecutable(path string) (string, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", e
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, e := os.Stat(p)
		if e != nil {
			return "", e
		}
		v, ok := st.Sys().(*syscall.Stat_t)
		if !ok || v.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return "", errors.New("untrusted native executable path")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return resolved, nil
}
