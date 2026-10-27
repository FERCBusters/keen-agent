package nativeposture

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"path/filepath"
	"syscall"
)

func prepareCommand(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		system = `C:\Windows\System32`
	}
	root := filepath.Dir(system)
	c.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PSModulePath=" + filepath.Join(system, `WindowsPowerShell\v1.0\Modules`)}
	c.Dir = root
}

func trustedExecutable(path string) (string, error) { return path, nil }
