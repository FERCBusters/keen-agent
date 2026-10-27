//go:build !windows

package nativeposture

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func privatePath(path string, dir bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("private path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return errors.New("private path must be root owned and not writable by others or symlinked")
		}
		if p == filepath.Clean(path) {
			if st.IsDir() != dir || (!dir && !st.Mode().IsRegular()) || st.Mode().Perm()&0077 != 0 {
				return errors.New("private file/directory requires mode 0600/0700")
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
