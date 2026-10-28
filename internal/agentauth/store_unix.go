//go:build !windows

package agentauth

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

// IdentityFile is the private identity's name inside the state directory.
const IdentityFile = "identity.json"

// FileStore keeps identity.json in a private (0700) directory owned by the
// running user. Writes go through directory descriptors with O_EXCL and
// O_NOFOLLOW, then an fsync and rename, so a crash leaves the old or the new
// identity, never a partial one, and links are never followed.
type FileStore struct {
	Dir string
	// Owner, when set, is chowned onto the identity after a write by root
	// (the setup helper enrolling on behalf of a service account).
	Owner *Owner
}

// Owner names the numeric owner for files written on a service's behalf.
type Owner struct{ UID, GID int }

func (f FileStore) dir() (*os.File, error) {
	fd, err := unix.Open(f.Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), f.Dir)
	st, err := d.Stat()
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		d.Close()
		return nil, errors.New("identity directory must be private (0700)")
	}
	return d, nil
}

func (f FileStore) Load() (Identity, error) {
	var id Identity
	if !filepath.IsAbs(f.Dir) {
		return id, errors.New("state directory must be absolute")
	}
	d, err := f.dir()
	if err != nil {
		return id, err
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), IdentityFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return id, os.ErrNotExist
		}
		return id, err
	}
	file := os.NewFile(uintptr(fd), IdentityFile)
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return id, errors.New("identity must be a private regular file (0600)")
	}
	b, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(b) > 16384 {
		return id, errors.New("identity file too large")
	}
	if json.Unmarshal(b, &id) != nil {
		return id, errors.New("invalid private identity; restore a backup or re-enrol")
	}
	return id, nil
}

func (f FileStore) Save(id Identity) (err error) {
	d, err := f.dir()
	if err != nil {
		return err
	}
	defer d.Close()
	suffix, err := NewSecret()
	if err != nil {
		return err
	}
	temporary := ".identity-" + suffix
	fd, err := unix.Openat(int(d.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer unix.Unlinkat(int(d.Fd()), temporary, 0)
	b, err := json.Marshal(id)
	if err == nil {
		_, err = file.Write(b)
	}
	if err == nil && f.Owner != nil {
		err = file.Chown(f.Owner.UID, f.Owner.GID)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat(int(d.Fd()), temporary, int(d.Fd()), IdentityFile); err != nil {
		return err
	}
	return d.Sync()
}
