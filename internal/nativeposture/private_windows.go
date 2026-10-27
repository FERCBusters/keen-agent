package nativeposture

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func privatePath(path string, dir bool) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if st.IsDir() != dir || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid private path")
	}
	// The private root and each target must allow only Administrators and SYSTEM.
	// Also reject reparse points in parents, including directory junctions.
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		u, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return e
		}
		a, e := windows.GetFileAttributes(u)
		if e != nil {
			return e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("private path contains reparse point")
		}
		if e := trustedParentACL(p); e != nil {
			return e
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if !dir {
		if e := privatePath(filepath.Dir(path), true); e != nil {
			return e
		}
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	trusted := func(s *windows.SID) bool {
		return s != nil && (s.String() == "S-1-5-18" || s.String() == "S-1-5-32-544")
	}
	owner, _, e := sd.Owner()
	if e != nil || !trusted(owner) {
		return errors.New("private path owner must be SYSTEM or Administrators")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errors.New("private path requires restrictive DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return e
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errors.New("private path permits an untrusted principal")
		}
	}
	return nil
}

// An untrusted owner or DELETE_CHILD/WRITE_DAC/WRITE_OWNER on any ancestor
// would permit replacing even an otherwise protected token or state directory.
func trustedParentACL(path string) error {
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	trusted := func(s *windows.SID) bool {
		if s == nil {
			return false
		}
		v := s.String()
		return v == "S-1-5-18" || v == "S-1-5-32-544" || v == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	}
	owner, _, e := sd.Owner()
	if e != nil || !trusted(owner) {
		return errors.New("private path has untrusted ancestor owner")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errors.New("private path has permissive ancestor ACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return e
		}
		if ace.Header.AceFlags&8 != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported private path ancestor ACE")
		}
		if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) && uint32(ace.Mask)&(0x40|0x40000|0x80000|0x10000000|0x40000000) != 0 {
			return errors.New("private path ancestor permits untrusted replacement")
		}
	}
	return nil
}
