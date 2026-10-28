package nativeposture

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A script the size of the Windows report and more, with multi-line blocks.
func largeScript() string {
	return "$items = New-Object System.Collections.Generic.List[object]\n" +
		"function Add-Item($n) { $items.Add(@{ name = $n }) }\n" +
		"if ($true) {\n  Add-Item 'one'\n}\nelse {\n  Add-Item 'never'\n}\n" +
		"# " + strings.Repeat("padding ", 6000) + "\n" +
		"try { throw 'x' } catch { Add-Item 'caught' }\n" +
		"ConvertTo-Json -InputObject @($items.ToArray()) -Depth 4 -Compress\n"
}

func TestReportScriptTravelsOnStandardInput(t *testing.T) {
	script := largeScript()
	args, input := windowsInvocation(script)
	line := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ` + strings.Join(args, " ")
	// Windows refuses command lines over 32,767 characters; the script size
	// must not matter.
	if len(line) > 2048 {
		t.Fatalf("command line is %d characters", len(line))
	}
	decoded, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil || string(decoded) != script {
		t.Fatal("script does not survive standard input")
	}
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed; command-line checks only")
	}
	cmd := exec.Command(pwsh, args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = append(os.Environ(), "POWERSHELL_TELEMETRY_OPTOUT=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != `[{"name":"one"},{"name":"caught"}]` {
		t.Fatalf("unexpected output %q", got)
	}
}
