package nativeposture

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestMacScreenLockStatus(t *testing.T) {
	for _, tc := range []struct{ name, output, required, delay string }{
		{"reported_sequoia_15_8_2", "screenLock delay is 300 seconds", "true", "300"},
		{"nslog", "2026-10-27 12:34:56.123 sysadminctl[123:456] screenLock delay is 300 seconds", "true", "300"},
		{"immediate", "screenLock delay is immediate", "true", "0"},
		{"zero", "screenLock delay is 0 seconds", "true", "0"},
		{"off", "screenLock is off", "false", ""},
		{"disabled", "screenLock is disabled", "false", ""},
		{"empty", "", "", ""},
		{"error", "Unable to access keychain", "", ""},
		{"malformed", "screenLock delay is -1 seconds", "", ""},
		{"unknown", "screenLock delay is unknown", "", ""},
		{"sentinel", "screenLock delay is 4294967295 seconds", "", ""},
		{"overflow", "screenLock delay is 99999999999999999999 seconds", "", ""},
		{"conflicting", "screenLock is off\nscreenLock delay is 300 seconds", "", ""},
		{"untrusted_prefix", "error: screenLock delay is 300 seconds", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMacScreenLock(tc.output)
			if tc.required == "" {
				if got != nil {
					t.Fatal(got)
				}
				return
			}
			if got["password_required"] != tc.required || got["password_delay_seconds"] != tc.delay {
				t.Fatal(got)
			}
		})
	}
}
func TestMacLiveScreenLockWithoutLegacyKeys(t *testing.T) {
	f := fakeRunner{
		"/usr/bin/stat -f %u /dev/console":                              "501",
		"/bin/launchctl " + strings.Join(macScreenLockArgs("501"), " "): "screenLock delay is 300 seconds",
	}
	for _, o := range CollectMac(context.Background(), f) {
		if o.Check == "screen_lock" {
			if o.Validate() != nil || o.Status != "observed" || o.Scope != "uid:501" || o.Reason != "sysadminctl_screen_lock_observed" || !reflect.DeepEqual(o.Facts, map[string]string{"password_required": "true", "password_delay_seconds": "300"}) {
				t.Fatal(o)
			}
			return
		}
	}
	t.Fatal("missing screen lock evidence")
}
func TestMacLiveScreenLockOverridesStalePasswordPreferences(t *testing.T) {
	for _, status := range []string{"screenLock is off", "screenLock delay is 300 seconds"} {
		f := fakeRunner{
			"/usr/bin/stat -f %u /dev/console":                                                              "501",
			"/bin/launchctl " + strings.Join(macScreenLockArgs("501"), " "):                                 status,
			"/usr/bin/defaults read /Library/Managed Preferences/com.apple.screensaver askForPassword":      "1",
			"/usr/bin/defaults read /Library/Managed Preferences/com.apple.screensaver askForPasswordDelay": "999",
			"/usr/bin/defaults read /Library/Managed Preferences/com.apple.screensaver idleTime":            "600",
		}
		found := false
		for _, o := range CollectMac(context.Background(), f) {
			if o.Check != "screen_lock" {
				continue
			}
			found = true
			want := parseMacScreenLock(status)
			want["idle_seconds"] = "600"
			if !reflect.DeepEqual(o.Facts, want) {
				t.Fatal(o)
			}
		}
		if !found {
			t.Fatal("missing screen lock")
		}
	}
}
func TestMacUnrecognisedStatusFallsBack(t *testing.T) {
	f := fakeRunner{
		"/usr/bin/stat -f %u /dev/console":                                                           "501",
		"/bin/launchctl " + strings.Join(macScreenLockArgs("501"), " "):                              "screenLock delay is unknown",
		"/usr/bin/sudo -n -H -u #501 -- /usr/bin/defaults read com.apple.screensaver askForPassword": "0",
	}
	for _, o := range CollectMac(context.Background(), f) {
		if o.Check == "screen_lock" && o.Status == "observed" && o.Facts["password_required"] == "false" && o.Reason == "user_preferences_observed" {
			return
		}
	}
	t.Fatal("legacy fallback lost")
}
func TestMacStatusCaptureOnlyForFixedConsoleUserQuery(t *testing.T) {
	if !isMacScreenLockQuery("/bin/launchctl", macScreenLockArgs("501")) {
		t.Fatal("status stderr would be discarded")
	}
	for _, uid := range []string{"0", "499", "501;id", "-1", "4294967296"} {
		if isMacScreenLockQuery("/bin/launchctl", macScreenLockArgs(uid)) {
			t.Fatal(uid)
		}
	}
	args := macScreenLockArgs("501")
	args[len(args)-1] = "off"
	if isMacScreenLockQuery("/bin/launchctl", args) || isMacScreenLockQuery("/usr/bin/defaults", macScreenLockArgs("501")) {
		t.Fatal("non-status stderr captured")
	}
}
