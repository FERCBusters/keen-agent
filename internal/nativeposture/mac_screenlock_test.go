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
			if want["password_required"] == "true" {
				want["automatic_lock_configured"], want["lock_after_seconds"], want["lock_paths"] = "true", "900", "screen_saver"
			} else {
				want["automatic_lock_configured"] = "false"
			}
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

const pmsetLaptop = `Battery Power:
 Sleep On Power Button 1
 lowpowermode         0
 standby              1
 sleep                1 (sleep prevented by coreaudiod)
 displaysleep         2
AC Power:
 Sleep On Power Button 1
 sleep                1
 displaysleep         10
`

func TestPmsetProfiles(t *testing.T) {
	got := parsePmset(pmsetLaptop)
	if !reflect.DeepEqual(got, map[string]macPowerSource{"Battery": {2, 1}, "AC": {10, 1}}) {
		t.Fatal(got)
	}
	desktop := parsePmset("AC Power:\n sleep 0\n displaysleep 15\n")
	if !reflect.DeepEqual(desktop, map[string]macPowerSource{"AC": {15, 0}}) {
		t.Fatal(desktop)
	}
	for name, raw := range map[string]string{
		"empty":            "",
		"no AC profile":    "Battery Power:\n sleep 1\n displaysleep 2\n",
		"missing setting":  "AC Power:\n displaysleep 10\n",
		"repeated setting": "AC Power:\n sleep 1\n displaysleep 10\n displaysleep 5\n",
		"repeated profile": "AC Power:\n sleep 1\n displaysleep 10\nAC Power:\n sleep 1\n displaysleep 10\n",
		"negative":         "AC Power:\n sleep -1\n displaysleep 10\n",
	} {
		if got := parsePmset(raw); got != nil {
			t.Fatalf("%s: %v", name, got)
		}
	}
}

func TestMacLockPaths(t *testing.T) {
	laptop := parsePmset(pmsetLaptop)
	for _, tc := range []struct {
		name  string
		facts map[string]string
		power map[string]macPowerSource
		want  map[string]string
	}{
		// The reported Mac: no screen saver time set, so the display path decides.
		{"display sleep with delay", map[string]string{"password_required": "true", "password_delay_seconds": "300"}, laptop,
			map[string]string{"automatic_lock_configured": "true", "lock_after_seconds": "360", "lock_paths": "display_sleep", "batteries_present": "true"}},
		{"slowest profile counts", map[string]string{"password_required": "true", "password_delay_seconds": "0"}, map[string]macPowerSource{"Battery": {2, 0}, "AC": {30, 0}},
			map[string]string{"automatic_lock_configured": "true", "lock_after_seconds": "1800", "lock_paths": "display_sleep", "batteries_present": "true"}},
		{"screen saver first", map[string]string{"password_required": "true", "password_delay_seconds": "0", "idle_seconds": "300"}, map[string]macPowerSource{"AC": {20, 0}},
			map[string]string{"automatic_lock_configured": "true", "lock_after_seconds": "300", "lock_paths": "display_sleep,screen_saver", "batteries_present": "false"}},
		{"a profile that never turns off", map[string]string{"password_required": "true", "password_delay_seconds": "0"}, map[string]macPowerSource{"Battery": {2, 1}, "AC": {0, 0}},
			map[string]string{"batteries_present": "true"}},
		{"never and no screen saver", map[string]string{"password_required": "true", "password_delay_seconds": "0", "idle_seconds": "0"}, map[string]macPowerSource{"AC": {0, 0}},
			map[string]string{"automatic_lock_configured": "false", "batteries_present": "false"}},
		{"password off", map[string]string{"password_required": "false"}, laptop,
			map[string]string{"automatic_lock_configured": "false"}},
		{"pmset unavailable", map[string]string{"password_required": "true", "password_delay_seconds": "300"}, nil,
			map[string]string{}},
		{"delay unknown", map[string]string{"password_required": "true"}, laptop,
			map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := map[string]string{}
			for k, v := range tc.facts {
				f[k] = v
			}
			macLockPaths(f, tc.power)
			for k := range tc.facts {
				delete(f, k)
			}
			if !reflect.DeepEqual(f, tc.want) {
				t.Fatal(f)
			}
		})
	}
}

func TestMacCollectorReadsDisplaySleep(t *testing.T) {
	f := fakeRunner{
		"/usr/bin/stat -f %u /dev/console":                              "501",
		"/bin/launchctl " + strings.Join(macScreenLockArgs("501"), " "): "screenLock delay is 300 seconds",
		"/usr/bin/pmset -g custom":                                      pmsetLaptop,
	}
	for _, o := range CollectMac(context.Background(), f) {
		if o.Check == "screen_lock" {
			if o.Validate() != nil || o.Facts["automatic_lock_configured"] != "true" || o.Facts["lock_after_seconds"] != "360" {
				t.Fatal(o)
			}
			return
		}
	}
	t.Fatal("missing screen lock evidence")
}
