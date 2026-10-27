package nativeposture

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unicode/utf16"
)

//go:embed windows-report.ps1
var windowsReport string

func Collect(ctx context.Context, r Runner) ([]Observation, error) {
	// Embed the fixed read-only script in the signed executable. No script file,
	// remote code, user expressions or ExecutionPolicy bypass is accepted.
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return nil, e
	}
	words := utf16.Encode([]rune(windowsReport))
	b := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	out, e := r.Run(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)}, nil)
	if e != nil {
		return nil, e
	}
	return DecodeObservations(out)
}
