package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	p "keen-agent/internal/nativeposture"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
func configRoot() string {
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return ""
	}
	return filepath.Join(root, "KEEN", "Posture")
}
func configPath() string { return filepath.Join(configRoot(), "config.json") }
func secure(path string, dir bool) error {
	sddl := "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if dir {
		sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
}
func privateDir(path string) error {
	if e := p.CheckTrustedAncestors(filepath.Dir(path)); e != nil {
		return e
	}
	if e := os.Mkdir(path, 0700); e == nil {
		return secure(path, true)
	} else if !os.IsExist(e) {
		return e
	}
	if e := p.CheckTrustedAncestors(path); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() {
		return errors.New("invalid directory")
	}
	return secure(path, true)
}
func prepare() error {
	root := configRoot()
	if root == "" {
		return errors.New("ProgramData unavailable")
	}
	if e := privateDir(filepath.Dir(root)); e != nil {
		return e
	}
	if e := privateDir(root); e != nil {
		return e
	}
	return privateDir(filepath.Join(root, "state"))
}
func protectFile(path string) error { return secure(path, false) }
func configBytes(r Request) []byte {
	b, _ := json.Marshal(map[string]any{"endpoint": r.URL, "token_file": filepath.Join(configRoot(), "token"), "state_dir": filepath.Join(configRoot(), "state"), "interval_seconds": 3600})
	return b
}
func activate(ctx context.Context) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("KeenPosture")
	if e != nil {
		return e
	}
	defer s.Close()
	cfg, e := s.Config()
	if e != nil {
		return e
	}
	cfg.StartType = mgr.StartAutomatic
	if e = s.UpdateConfig(cfg); e != nil {
		return e
	}
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State == svc.Running {
		return nil
	}
	if e = s.Start(); e != nil {
		return e
	}
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			status, e = s.Query()
			if e != nil {
				return e
			}
			if status.State == svc.Running {
				return nil
			}
			if status.State == svc.Stopped {
				return errors.New("service stopped")
			}
		}
	}
}

func OpenRequest(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return nil, errors.New("local absolute path required")
	}
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(u, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	e = windows.GetFileInformationByHandle(h, &info)
	if e != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("regular request required")
	}
	if e = privateRequest(path, h); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}

func privateRequest(path string, handle windows.Handle) error {
	var expected string
	for _, name := range []string{filepath.Dir(path), path} {
		var sd *windows.SECURITY_DESCRIPTOR
		var e error
		if name == path {
			sd, e = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		} else {
			sd, e = windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		}
		if e != nil {
			return e
		}
		owner, _, e := sd.Owner()
		if e != nil || owner == nil {
			return errors.New("request owner missing")
		}
		sid := owner.String()
		if sid == "S-1-5-18" || sid == "S-1-5-32-544" {
			return errors.New("user-owned request required")
		}
		if expected != "" && sid != expected {
			return errors.New("request owner mismatch")
		}
		expected = sid
		acl, _, e := sd.DACL()
		if e != nil || acl == nil {
			return errors.New("private request DACL required")
		}
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if e = windows.GetAce(acl, i, &ace); e != nil {
				return e
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return errors.New("unsupported request ACL")
			}
			principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			if principal != sid && principal != "S-1-5-18" && principal != "S-1-5-32-544" {
				return errors.New("request readable by another user")
			}
		}
	}
	return nil
}
