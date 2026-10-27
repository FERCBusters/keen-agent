//go:build linux || darwin

package onboarding

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRequestCannotFollowSymlinkOrBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "request")
	os.WriteFile(file, []byte("{}"), 0600)
	f, e := OpenRequest(file)
	if os.Geteuid() == 0 {
		if e == nil {
			f.Close()
			t.Fatal("root-owned request accepted")
		}
	} else {
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(file, link); e != nil {
		t.Fatal(e)
	}
	if f, e = OpenRequest(link); e == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if e = syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if f, e = OpenRequest(fifo); e == nil {
		f.Close()
		t.Fatal("FIFO accepted")
	}
}
