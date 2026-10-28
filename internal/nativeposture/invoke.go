package nativeposture

import (
	"encoding/base64"
	"encoding/binary"
	"unicode/utf16"
)

// bootstrap reads the report script from standard input, as base64 so the
// console code page cannot alter it, and runs it. It is the only code on the
// command line.
const bootstrap = `$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()));& ([scriptblock]::Create($s))`

// windowsInvocation returns powershell.exe arguments and standard input that
// run script. Windows limits a command line to 32,767 characters, which the
// encoded report script exceeds, so the script travels on standard input.
func windowsInvocation(script string) ([]string, []byte) {
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand(bootstrap)},
		[]byte(base64.StdEncoding.EncodeToString([]byte(script)))
}

// encodedCommand is PowerShell's -EncodedCommand form: base64 of UTF-16LE.
func encodedCommand(command string) string {
	words := utf16.Encode([]rune(command))
	b := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	return base64.StdEncoding.EncodeToString(b)
}
