package nativeposture

import (
	"context"
	_ "embed"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

//go:embed windows-report.ps1
var windowsReport string

// powrprof.dll is loaded from System32 only.
var getPwrCapabilities = windows.NewLazySystemDLL("powrprof.dll").NewProc("GetPwrCapabilities")

// powerCapabilities reads SYSTEM_POWER_CAPABILITIES (76 bytes) directly, so the
// script never compiles code to make the call. It returns a fixed PowerShell
// assignment of three booleans, or nothing when the query is unavailable.
func powerCapabilities() string {
	if getPwrCapabilities.Find() != nil {
		return ""
	}
	var caps [128]byte
	ok, _, _ := getPwrCapabilities.Call(uintptr(unsafe.Pointer(&caps[0])))
	if byte(ok) == 0 {
		return ""
	}
	return powerCapabilitiesPrelude(caps[:])
}

func Collect(ctx context.Context, r Runner) ([]Observation, error) {
	// Embed the fixed read-only script in the signed executable. No script file,
	// remote code, user expressions or ExecutionPolicy bypass is accepted.
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return nil, e
	}
	args, input := windowsInvocation(powerCapabilities() + windowsReport)
	out, e := r.Run(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), args, input)
	if e != nil {
		return nil, e
	}
	return DecodeObservations(out)
}
