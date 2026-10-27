package posture

import (
	"context"
	"errors"
	"keen-agent/internal/posturemodel"
	"os"
	"testing"
)

func TestFailureReason(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		ctx    error
		want   string
	}{{"Permission denied (you must be root)", nil, "permission_denied"}, {"Operation not permitted", nil, "permission_denied"}, {"table does not exist", nil, "filter_table_absent"}, {"", context.DeadlineExceeded, "query_timed_out"}, {"unknown option", nil, "command_failed"}} {
		e := commandError("iptables-save", errors.New("exit 1"), tc.ctx, tc.stderr)
		if FailureReason(e) != tc.want {
			t.Fatal(e)
		}
	}
	if FailureReason(os.ErrNotExist) != "tool_not_installed" {
		t.Fatal("missing tool")
	}
}
func TestQubesNoLocalDiskClaim(t *testing.T) {
	s := fixture()
	s.files["/usr/share/qubes/marker-vm"] = ""
	all := Host(context.Background(), s)
	count := 0
	for _, o := range all {
		if o.Provider == "qubes" {
			count++
			if o.Facts["encrypted"] != "" || o.Facts["enabled"] != "" || o.Reason != "managed_outside_qube" {
				t.Fatal(o)
			}
		}
	}
	if count != 3 {
		t.Fatal(all)
	}
	for _, c := range s.calls {
		if len(c) >= 5 && c[:5] == "lsblk" {
			t.Fatal("queried guest disk", c)
		}
	}
	d := Desktop(context.Background(), s)
	if len(d) != 1 || d[0].Provider != "qubes" {
		t.Fatal(d)
	}
}
func TestQuietEvidence(t *testing.T) {
	a := observation("firewall", "iptables", "host")
	b := a
	b.Status = "observed"
	b.Facts = map[string]string{"enabled": "false"}
	got := posturemodel.Evidence([]Observation{a, b})
	if len(got) != 1 || got[0].Facts["enabled"] != "false" {
		t.Fatal(got)
	}
}
func TestXenAloneIsNotQubes(t *testing.T) {
	s := fixture()
	s.files["/sys/hypervisor/type"] = "xen"
	if IsQubes(s) {
		t.Fatal("generic Xen incorrectly labeled Qubes")
	}
}
func TestMulticallInvocationPreserved(t *testing.T) {
	c := probeCommand(context.Background(), "/usr/sbin/xtables-nft-multi", "/usr/sbin/iptables-save", "-t", "filter")
	if c.Path != "/usr/sbin/xtables-nft-multi" || c.Args[0] != "/usr/sbin/iptables-save" || c.Args[1] != "-t" {
		t.Fatal(c.Path, c.Args)
	}
}
