package agentauth

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// IdentityFile is the private identity's name inside the state directory.
const IdentityFile = "identity.json"

// Owner is unused on Windows; the protected directory's ACL applies.
type Owner struct{ UID, GID int }

// FileStore keeps identity.json in a state directory the caller has already
// verified as private (Administrators and SYSTEM only, no reparse points).
type FileStore struct {
	Dir   string
	Owner *Owner
	// Check verifies the directory or file before each use.
	Check func(path string, dir bool) error
}

func (f FileStore) check(path string, dir bool) error {
	if f.Check == nil {
		return errors.New("identity store requires a private path check")
	}
	return f.Check(path, dir)
}

func (f FileStore) Load() (Identity, error) {
	var id Identity
	if !filepath.IsAbs(f.Dir) {
		return id, errors.New("state directory must be absolute")
	}
	if err := f.check(f.Dir, true); err != nil {
		return id, err
	}
	path := filepath.Join(f.Dir, IdentityFile)
	if _, err := os.Lstat(path); err != nil {
		return id, err
	}
	if err := f.check(path, false); err != nil {
		return id, err
	}
	file, err := os.Open(path)
	if err != nil {
		return id, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(b) > 16384 {
		return id, errors.New("identity file too large")
	}
	if json.Unmarshal(b, &id) != nil {
		return id, errors.New("invalid private identity; restore a backup or re-enrol")
	}
	return id, nil
}

func (f FileStore) Save(id Identity) error {
	if err := f.check(f.Dir, true); err != nil {
		return err
	}
	suffix, err := NewSecret()
	if err != nil {
		return err
	}
	temporary := filepath.Join(f.Dir, ".identity-"+suffix)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	b, err := json.Marshal(id)
	if err == nil {
		_, err = file.Write(b)
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
	// The new file inherits the protected directory's ACL; a rename replaces
	// the old identity atomically on NTFS.
	return os.Rename(temporary, filepath.Join(f.Dir, IdentityFile))
}
