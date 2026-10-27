package posture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeSystem struct {
	commands map[string]string
	files    map[string]string
	globs    map[string][]string
	env      map[string]string
	calls    []string
}

func fixture() *fakeSystem {
	return &fakeSystem{commands: map[string]string{}, files: map[string]string{}, globs: map[string][]string{}, env: map[string]string{}}
}
func commandKey(n string, a ...string) string { return n + " " + strings.Join(a, " ") }
func (s *fakeSystem) Run(_ context.Context, n string, a ...string) ([]byte, error) {
	k := commandKey(n, a...)
	s.calls = append(s.calls, k)
	v, ok := s.commands[k]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}
func (s *fakeSystem) Read(p string) ([]byte, error) {
	v, ok := s.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}
func (s *fakeSystem) Tail(p string) ([]byte, error) { return s.Read(p) }
func (s *fakeSystem) Glob(p string) ([]string, error) {
	v, ok := s.globs[p]
	if !ok {
		return nil, errors.New("unavailable")
	}
	return v, nil
}
func (s *fakeSystem) Env(k string) string { return s.env[k] }
func (*fakeSystem) UID() int              { return 1000 }
func (*fakeSystem) Now() time.Time        { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
func (s *fakeSystem) set(n string, args []string, out string) {
	s.commands[commandKey(n, args...)] = out
}
func find(t *testing.T, all []Observation, provider, scope string) Observation {
	t.Helper()
	for _, o := range all {
		if o.Provider == provider && (scope == "" || o.Scope == scope) {
			return o
		}
	}
	t.Fatalf("missing %s %s in %+v", provider, scope, all)
	return Observation{}
}
func TestStorageAncestry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes []block
		uuid  map[string]string
		want  string
	}{
		{"luks_then_lvm", []block{{Dev: "8:0", Type: "disk", Children: []block{{Dev: "8:1", Type: "part", Children: []block{{Dev: "253:0", Type: "crypt", Children: []block{{Dev: "253:1", Type: "lvm"}}}}}}}}, map[string]string{"253:0": "CRYPT-LUKS2-abcd-root"}, "true"},
		{"lvm_then_luks", []block{{Dev: "8:0", Type: "disk", Children: []block{{Dev: "253:0", Type: "lvm", Children: []block{{Dev: "253:1", Type: "crypt"}}}}}}, map[string]string{"253:1": "CRYPT-LUKS1-abcd-root"}, "true"},
		{"plain_partition", []block{{Dev: "8:0", Type: "disk", Children: []block{{Dev: "253:1", Type: "part"}}}}, nil, "false"},
		{"plain_dmcrypt_cipher_unknown", []block{{Dev: "253:1", Type: "crypt"}}, map[string]string{"253:1": "CRYPT-PLAIN-root"}, "unknown"},
		{"loop_backing_unknown", []block{{Dev: "253:1", Type: "loop"}}, nil, "unknown"},
		{"crypt_permission_denied", []block{{Dev: "253:1", Type: "crypt"}}, nil, "unknown"},
		{"zram", []block{{Dev: "253:1", KName: "/dev/zram0", Type: "disk"}}, nil, "not_applicable"},
		{"unknown_device_mapper", []block{{Dev: "253:1", Type: "dm"}}, nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			for id, u := range tc.uuid {
				s.files["/sys/dev/block/"+id+"/dm/uuid"] = u
			}
			got, _ := encryption(s, blockGraph(tc.nodes), "253:1", map[string]bool{})
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
func TestRAIDAllBranchesMustBeEncrypted(t *testing.T) {
	nodes := []block{{Dev: "8:0", Type: "disk", Children: []block{{Dev: "253:0", Type: "crypt", Children: []block{{Dev: "9:0", Type: "raid1"}}}}}, {Dev: "8:16", Type: "disk", Children: []block{{Dev: "9:0", Type: "raid1"}}}}
	s := fixture()
	s.files["/sys/dev/block/253:0/dm/uuid"] = "CRYPT-LUKS2-a"
	v, _ := encryption(s, blockGraph(nodes), "9:0", map[string]bool{})
	if v != "false" {
		t.Fatalf("mixed RAID passed: %s", v)
	}
	nodes[1].Children = []block{{Dev: "253:2", Type: "crypt", Children: []block{{Dev: "9:0", Type: "raid1"}}}}
	s.files["/sys/dev/block/253:2/dm/uuid"] = "CRYPT-LUKS2-b"
	v, _ = encryption(s, blockGraph(nodes), "9:0", map[string]bool{})
	if v != "true" {
		t.Fatal(v)
	}
}
func TestStorageCycles(t *testing.T) {
	s := fixture()
	g := map[string]*device{"1:1": {block{Dev: "1:1", Type: "lvm"}, map[string]bool{"1:2": true}}, "1:2": {block{Dev: "1:2", Type: "lvm"}, map[string]bool{"1:1": true}}}
	v, _ := encryption(s, g, "1:1", map[string]bool{})
	if v != "unknown" {
		t.Fatal(v)
	}
}
func TestBtrfsMultipleDevices(t *testing.T) {
	s := fixture()
	g := blockGraph([]block{{Dev: "253:0", Type: "crypt", UUID: "12345678-abcd"}, {Dev: "8:1", Type: "part"}})
	s.files["/sys/dev/block/253:0/dm/uuid"] = "CRYPT-LUKS2-a"
	pattern := "/sys/fs/btrfs/12345678-abcd/devices/*/dev"
	s.globs[pattern] = []string{"/test/a", "/test/b"}
	s.files["/test/a"] = "253:0"
	s.files["/test/b"] = "8:1"
	o := mountEncryption(s, g, mount{Target: "/home", FSType: "btrfs", Dev: "253:0"})
	if o.Facts["encrypted"] != "false" {
		t.Fatalf("mixed btrfs passed: %+v", o)
	}
	delete(s.files, "/test/b")
	o = mountEncryption(s, g, mount{Target: "/home", FSType: "btrfs", Dev: "253:0"})
	if o.Status != "unknown" {
		t.Fatal(o)
	}
}
func TestDiskInventorySwapAndBoot(t *testing.T) {
	s := fixture()
	s.set("lsblk", []string{"--json", "--paths", "--output", "NAME,KNAME,TYPE,FSTYPE,UUID,MAJ:MIN"}, `{"blockdevices":[{"name":"/dev/sda1","kname":"/dev/sda1","type":"part","maj:min":"8:1"},{"name":"/dev/mapper/root","type":"crypt","maj:min":"253:0"}]}`)
	s.files["/sys/dev/block/253:0/dm/uuid"] = "CRYPT-LUKS2-root"
	args := []string{"--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,MAJ:MIN"}
	s.set("findmnt", args, `{"filesystems":[{"target":"/","fstype":"ext4","maj:min":"253:0"},{"target":"/boot","fstype":"ext4","maj:min":"8:1"}]}`)
	s.files["/proc/swaps"] = "Filename Type Size Used Priority\n/swapfile file 123 0 -2\n/dev/sda1 partition 123 0 -3\n"
	s.set("findmnt", append(append([]string{}, args...), "--target", "/swapfile"), `{"filesystems":[{"target":"/","fstype":"ext4","maj:min":"253:0"}]}`)
	all := Disks(context.Background(), s)
	if find(t, all, "linux_block", "swap:/swapfile").Facts["encrypted"] != "true" {
		t.Fatal(all)
	}
	if find(t, all, "linux_block", "swap:/dev/sda1").Facts["encrypted"] != "false" {
		t.Fatal(all)
	}
	if find(t, all, "linux_block", "/boot").Status != "not_applicable" {
		t.Fatal(all)
	}
}
func TestNFTDockerOnlyNotProtection(t *testing.T) {
	o := inspectNFT([]byte(`{"nftables":[{"chain":{"family":"ip","hook":"forward","policy":"drop"}},{"rule":{"expr":[]}}]}`))
	if o.Facts["input_base_chains"] != "0" || o.Facts["effective_protection"] != "not_evaluated" {
		t.Fatal(o)
	}
	for _, bad := range []string{`{}`, `null`, `{"nftables":"oops"}`, `garbage`} {
		if o := inspectNFT([]byte(bad)); o.Status != "unknown" {
			t.Fatal(o)
		}
	}
}
func TestNFTInputPolicies(t *testing.T) {
	o := inspectNFT([]byte(`{"nftables":[{"chain":{"family":"inet","hook":"input","policy":"drop"}},{"chain":{"family":"ip6","hook":"input","policy":"accept"}}]}`))
	if o.Facts["input_base_chains"] != "2" || o.Facts["input_drop_policy_chains"] != "1" {
		t.Fatal(o)
	}
}
func TestAPTConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"enabled", `APT::Periodic::Unattended-Upgrade "1";`, "true"}, {"disabled", `APT::Periodic::Unattended-Upgrade "0";`, "false"},
		{"always", `APT::Periodic::Unattended-Upgrade "always";`, "true"}, {"missing", "", "false"},
		{"invalid", `APT::Periodic::Unattended-Upgrade "garbage";`, ""},
		{"global_disable", "APT::Periodic::Enable \"0\";\nAPT::Periodic::Unattended-Upgrade \"1\";", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			s.set("apt-config", []string{"dump"}, tc.config)
			o := find(t, Updates(context.Background(), s), "apt", "")
			if o.Facts["automatic_install_configured"] != tc.want {
				t.Fatal(o)
			}
		})
	}
}
func TestDNFDownloadIsNotInstall(t *testing.T) {
	s := fixture()
	s.files["/etc/dnf/automatic.conf"] = "[commands]\ndownload_updates = yes\napply_updates = no\nupgrade_type = security\n"
	all := Updates(context.Background(), s)
	for _, p := range []string{"dnf", "dnf5"} {
		o := find(t, all, p, "")
		if o.Facts["automatic_install_configured"] != "false" || o.Facts["package_scope"] != "security" {
			t.Fatal(o)
		}
	}
	if o := find(t, all, "dnf_install", ""); o.Facts["automatic_install_configured"] != "true" {
		t.Fatal(o)
	}
}
func TestRPMOstreeStageIsNotApplied(t *testing.T) {
	s := fixture()
	s.files["/etc/rpm-ostreed.conf"] = "[Daemon]\nAutomaticUpdatePolicy=stage\n"
	o := find(t, Updates(context.Background(), s), "rpm_ostree", "")
	if o.Facts["automatic_install_configured"] != "false" {
		t.Fatal(o)
	}
}
func TestDefenderWhitelistsHealthAndDoesNotLeakTenant(t *testing.T) {
	s := fixture()
	s.set("mdatp", []string{"health", "--output", "json"}, `{"healthy":true,"real_time_protection_enabled":false,"passive_mode_enabled":true,"org_id":"SECRET"}`)
	o := find(t, Antivirus(context.Background(), s), "microsoft_defender", "")
	if o.Facts["real_time_protection_enabled"] != "false" || o.Status != "observed" {
		t.Fatal(o)
	}
	b, _ := json.Marshal(o)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal(string(b))
	}
}
func TestClamdAloneNeverClaimsOnAccessProtection(t *testing.T) {
	s := fixture()
	s.globs["/proc/[0-9]*/comm"] = []string{"/proc/1/comm"}
	s.files["/proc/1/comm"] = "clamd\n"
	o := find(t, Antivirus(context.Background(), s), "clamav", "")
	if o.Facts["clamd_process_present"] != "true" || o.Facts["clamonacc_process_present"] != "false" || o.Reason != "components_detected" {
		t.Fatal(o)
	}
}
func desktopFixture(desktop string) *fakeSystem {
	s := fixture()
	s.set("loginctl", []string{"list-sessions", "--no-legend", "--no-pager"}, "2 1000 alice seat0 tty2 active\n")
	s.set("loginctl", []string{"show-session", "2", "--no-pager", "--property=User,Type,Class,Desktop,Active,LockedHint,Remote"}, "User=1000\nType=wayland\nClass=user\nDesktop="+desktop+"\nActive=yes\nLockedHint=no\n")
	return s
}
func ownBus(s *fakeSystem, bus string) {
	s.set("busctl", []string{"--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", bus}, `s ":1.42"`)
}
func gnomeFixture() *fakeSystem {
	s := desktopFixture("GNOME")
	for k, v := range map[string]string{"org.gnome.desktop.screensaver lock-enabled": "true", "org.gnome.desktop.screensaver lock-delay": "uint32 0", "org.gnome.desktop.session idle-delay": "uint32 300", "org.gnome.desktop.lockdown disable-lock-screen": "false"} {
		s.commands["gsettings get "+k] = v
	}
	ownBus(s, "org.gnome.ScreenSaver")
	return s
}
func TestGNOMELockCornerCases(t *testing.T) {
	for _, tc := range []struct{ name, key, value, want string }{
		{"normal", "", "", "true"}, {"no_idle", "org.gnome.desktop.session idle-delay", "uint32 0", "false"},
		{"policy_disables", "org.gnome.desktop.lockdown disable-lock-screen", "true", "false"},
		{"lock_disabled", "org.gnome.desktop.screensaver lock-enabled", "false", "false"},
		{"invalid_idle", "org.gnome.desktop.session idle-delay", "-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := gnomeFixture()
			if tc.key != "" {
				s.commands["gsettings get "+tc.key] = tc.value
			}
			o := Desktop(context.Background(), s)[0]
			if o.Facts["automatic_lock_configured"] != tc.want {
				t.Fatal(o)
			}
		})
	}
}
func TestMissingLockerAndMultiSessionNeverPass(t *testing.T) {
	s := gnomeFixture()
	for k := range s.commands {
		if strings.HasPrefix(k, "busctl ") {
			delete(s.commands, k)
		}
	}
	o := Desktop(context.Background(), s)[0]
	if o.Status != "unknown" || o.Facts["automatic_lock_configured"] != "" {
		t.Fatal(o)
	}
	s = gnomeFixture()
	s.set("loginctl", []string{"list-sessions", "--no-legend", "--no-pager"}, "2 1000 alice\n3 1000 alice\n")
	s.set("loginctl", []string{"show-session", "3", "--no-pager", "--property=User,Type,Class,Desktop,Active,LockedHint,Remote"}, "User=1000\nType=x11\nClass=user\nDesktop=GNOME\n")
	o = Desktop(context.Background(), s)[0]
	if o.Reason != "multiple_graphical_sessions_for_uid" {
		t.Fatal(o)
	}
}
func TestNoSessionAndUnsupportedDesktop(t *testing.T) {
	s := fixture()
	s.set("loginctl", []string{"list-sessions", "--no-legend", "--no-pager"}, "")
	if o := Desktop(context.Background(), s)[0]; o.Status != "not_applicable" {
		t.Fatal(o)
	}
	s = desktopFixture("sway")
	if o := Desktop(context.Background(), s)[0]; o.Status != "unsupported" {
		t.Fatal(o)
	}
}
func TestXFCEUnitsAndMissingDefaults(t *testing.T) {
	s := desktopFixture("XFCE")
	ownBus(s, "org.xfce.ScreenSaver")
	for k, v := range map[string]string{"/lock/enabled": "true", "/saver/enabled": "true", "/saver/idle-activation/enabled": "true", "/lock/saver-activation/enabled": "true", "/saver/idle-activation/delay": "5", "/lock/saver-activation/delay": "1"} {
		s.commands["xfconf-query --channel xfce4-screensaver --property "+k] = v
	}
	o := Desktop(context.Background(), s)[0]
	if o.Facts["total_idle_to_lock_seconds"] != "360" {
		t.Fatal(o)
	}
	delete(s.commands, "xfconf-query --channel xfce4-screensaver --property /lock/enabled")
	if o := Desktop(context.Background(), s)[0]; o.Status != "unknown" {
		t.Fatal(o)
	}
}
func TestObservationsCannotOverwriteAuthority(t *testing.T) {
	for _, k := range []string{"authority", "status", "subject_uid", "check", "observed_at", "provider", "schema_version"} {
		o := observation("screen_lock", "gnome", "session")
		o.Facts[k] = "forged"
		if o.Validate() == nil {
			t.Fatalf("accepted reserved %s", k)
		}
	}
	o := observation("screen_lock", "gnome", "session")
	o.Status = "pass"
	if o.Validate() == nil {
		t.Fatal("accepted compliance verdict")
	}
}
func TestBoundedObservationAndOutput(t *testing.T) {
	o := observation("screen_lock", "gnome", "session")
	o.Facts["long"] = strings.Repeat("x", 1025)
	if o.Validate() == nil {
		t.Fatal("unbounded value")
	}
	var b capped
	if _, e := b.Write(make([]byte, MaxOutput+1)); e == nil {
		t.Fatal("unbounded subprocess output")
	}
}
func TestAllUnavailableRemainValidAndNoPass(t *testing.T) {
	s := fixture()
	for _, o := range Host(context.Background(), s) {
		if err := o.Validate(); err != nil {
			t.Fatal(o, err)
		}
		if o.Status == "observed" {
			t.Fatalf("unavailable passed %+v", o)
		}
	}
}
func FuzzNFT(f *testing.F) {
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o := inspectNFT(b)
		if e := o.Validate(); e != nil {
			t.Fatal(e)
		}
	})
}
func FuzzINI(f *testing.F) {
	f.Add([]byte("[commands]\napply_updates=yes"))
	f.Fuzz(func(t *testing.T, b []byte) { ini(b) })
}

func TestAPTNoopSuccessAndLaterError(t *testing.T) {
	s := fixture()
	s.set("apt-config", []string{"dump"}, `APT::Periodic::Unattended-Upgrade "1";`)
	s.files["/var/log/unattended-upgrades/unattended-upgrades.log"] = "2026-10-22 01:00:00,000 INFO Starting unattended upgrades script\n2026-10-22 01:00:10,000 INFO No packages found that can be upgraded unattended and no pending auto-removals\n2026-10-23 01:00:00,000 ERROR Network failed SECRET_URL\n"
	o := find(t, Updates(context.Background(), s), "apt", "")
	if o.Facts["error_after_last_success"] != "true" || o.Facts["last_success_local_time"] != "2026-10-22 01:00:10" {
		t.Fatal(o)
	}
	b, _ := json.Marshal(o)
	if strings.Contains(string(b), "SECRET_URL") {
		t.Fatal(string(b))
	}
}

func TestZFSNativeEncryptionAndLayering(t *testing.T) {
	s := fixture()
	args := []string{"get", "-H", "-p", "-o", "property,value", "encryption,encryptionroot,keystatus", "tank/home"}
	s.set("zfs", args, "encryption\taes-256-gcm\nencryptionroot\ttank\nkeystatus\tavailable")
	o := zfsEncryption(context.Background(), s, mount{Target: "/home", Source: "tank/home", FSType: "zfs"})
	if o.Facts["encrypted"] != "true" {
		t.Fatal(o)
	}
	s.set("zfs", args, "encryption\toff")
	o = zfsEncryption(context.Background(), s, mount{Target: "/home", Source: "tank/home"})
	if o.Status != "unknown" || o.Facts["encrypted"] != "" {
		t.Fatal(o)
	}
	o = zfsEncryption(context.Background(), s, mount{Target: "/home", Source: "--malicious"})
	if o.Reason != "invalid_or_unresolved_dataset" {
		t.Fatal(o)
	}
}

func TestKDEInstalledDefaultsAndFractionalTimeout(t *testing.T) {
	s := desktopFixture("KDE")
	ownBus(s, "org.freedesktop.ScreenSaver")
	s.files["/usr/share/config.kcfg/kscreenlockersettings.kcfg"] = `<kcfg><group name="Daemon"><entry key="Autolock"><default>true</default></entry><entry key="Timeout"><default>2.5</default></entry><entry key="LockGrace"><default>5</default></entry><entry key="LockOnResume"><default>true</default></entry><entry key="RequirePassword"><default>true</default></entry></group></kcfg>`
	for _, key := range []string{"Autolock", "Timeout", "LockGrace", "LockOnResume", "RequirePassword"} {
		s.set("kreadconfig6", []string{"--file", "kscreenlockerrc", "--group", "Daemon", "--key", key, "--default", "__KEEN_UNSET__"}, "__KEEN_UNSET__")
	}
	o := Desktop(context.Background(), s)[0]
	if o.Status != "observed" || o.Facts["idle_seconds"] != "150" || o.Facts["effective_protection"] != "not_evaluated" {
		t.Fatal(o)
	}
	if o.Facts["automatic_lock_configured"] != "" {
		t.Fatal("runtime policy not verified", o)
	}
}
func TestCinnamonAndMATEDelayUnits(t *testing.T) {
	for _, desktop := range []string{"Cinnamon", "MATE"} {
		s := desktopFixture(desktop)
		bus := "org.cinnamon.ScreenSaver"
		if desktop == "MATE" {
			bus = "org.mate.ScreenSaver"
		}
		ownBus(s, bus)
		prefix := "org.cinnamon.desktop"
		sessionSchema := prefix + ".session"
		delay, idle := "uint32 2", "uint32 300"
		want := "302"
		if desktop == "MATE" {
			prefix = "org.mate"
			sessionSchema = "org.mate.session"
			delay = "2"
			idle = "5"
			want = "420"
		}
		for key, v := range map[string]string{prefix + ".screensaver lock-enabled": "true", prefix + ".screensaver idle-activation-enabled": "true", prefix + ".screensaver lock-delay": delay, sessionSchema + " idle-delay": idle} {
			s.commands["gsettings get "+key] = v
		}
		o := Desktop(context.Background(), s)[0]
		if o.Facts["total_idle_to_lock_seconds"] != want {
			t.Fatal(desktop, o)
		}
	}
}
func TestXScreenSaverRequiresOwnProcess(t *testing.T) {
	s := fixture()
	s.env["HOME"] = "/home/alice"
	s.globs["/proc/[0-9]*/comm"] = []string{"/proc/12/comm"}
	s.files["/proc/12/comm"] = "xscreensaver"
	s.files["/proc/12/status"] = "Uid:\t1001\t1001\t1001\t1001\n"
	s.files["/home/alice/.xscreensaver"] = "timeout: 00:05:00\nlockTimeout: 00:00:10\nlock: True\nmode: random\n"
	if _, ok := xscreensaver(s, "session:2"); ok {
		t.Fatal("another user's process")
	}
	s.files["/proc/12/status"] = "Uid:\t1000\t1000\t1000\t1000\n"
	o, ok := xscreensaver(s, "session:2")
	if !ok || o.Status != "observed" || o.Facts["idle_seconds"] != "300" || o.Facts["automatic_lock_configured"] != "" {
		t.Fatal(o)
	}
}
func TestInvalidDurations(t *testing.T) {
	for _, v := range []string{"NaN", "+Inf", "-1", "1e100", "bogus"} {
		o := observation("screen_lock", "kde", "session")
		if fractionalSeconds(&o, "idle_seconds", v, 60) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"1:99:0", "-1:00:00", "foo", "1:2"} {
		if _, ok := clockDuration(v); ok {
			t.Fatal(v)
		}
	}
}

func TestPermissionFailureIsNotAbsence(t *testing.T) {
	s := fixture()
	all := Antivirus(context.Background(), s)
	for _, p := range []string{"sophos", "crowdstrike", "clamav"} {
		if o := find(t, all, p, ""); o.Status != "unknown" {
			t.Fatal(o)
		}
	}
}
func TestTrustedExecutableRejectsWritableAncestors(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root ownership check fixture")
	}
	dir := t.TempDir()
	p := dir + "/tool"
	if e := os.WriteFile(p, []byte("test"), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := trustedExecutable(p); e == nil {
		t.Fatal("accepted executable under world-writable /tmp")
	}
}
func TestLocalReadAndTailBounds(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/large"
	data := strings.Repeat("line\n", MaxOutput/5+100)
	if e := os.WriteFile(p, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	l := Local{}
	if _, e := l.Read(p); e == nil {
		t.Fatal("unbounded read")
	}
	b, e := l.Tail(p)
	if e != nil || len(b) > 128*1024 || !strings.HasPrefix(string(b), "line\n") {
		t.Fatal(len(b), e)
	}
	if _, e := l.Read(dir); e == nil {
		t.Fatal("read directory")
	}
	if _, e := l.Run(context.Background(), "sh", "-c", "true"); e == nil {
		t.Fatal("shell allowed")
	}
}

func TestDNF5VendorDefaultsAndOverrides(t *testing.T) {
	s := fixture()
	s.files["/usr/share/dnf5/dnf5-plugins/automatic.conf"] = "[commands]\napply_updates=yes\nupgrade_type=security\n"
	o := find(t, Updates(context.Background(), s), "dnf5", "")
	if o.Facts["automatic_install_configured"] != "true" || o.Facts["vendor_defaults_loaded"] != "true" {
		t.Fatal(o)
	}
	s.files["/etc/dnf/automatic.conf"] = "[commands]\napply_updates=no\n"
	o = find(t, Updates(context.Background(), s), "dnf5", "")
	if o.Facts["automatic_install_configured"] != "false" || o.Facts["package_scope"] != "security" {
		t.Fatal(o)
	}
}
