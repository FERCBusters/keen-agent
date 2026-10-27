package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type block struct {
	Name     string  `json:"name"`
	KName    string  `json:"kname"`
	Type     string  `json:"type"`
	FSType   string  `json:"fstype"`
	UUID     string  `json:"uuid"`
	Dev      string  `json:"maj:min"`
	Children []block `json:"children"`
}
type device struct {
	block
	Parents map[string]bool
}
type mount struct {
	Target string `json:"target"`
	Source string `json:"source"`
	FSType string `json:"fstype"`
	Dev    string `json:"maj:min"`
}

var devNumber = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
var fsUUID = regexp.MustCompile(`^[a-fA-F0-9-]{8,64}$`)

func blockGraph(nodes []block) map[string]*device {
	graph := map[string]*device{}
	var walk func([]block, string, int)
	walk = func(list []block, parent string, depth int) {
		if depth > 32 {
			return
		}
		for _, n := range list {
			if !devNumber.MatchString(n.Dev) {
				continue
			}
			d := graph[n.Dev]
			if d == nil {
				d = &device{n, map[string]bool{}}
				graph[n.Dev] = d
			}
			if parent != "" {
				d.Parents[parent] = true
			}
			walk(n.Children, n.Dev, depth+1)
		}
	}
	walk(nodes, "", 0)
	return graph
}

// All backing branches must be encrypted. Stop at a recognised LUKS mapping:
// an unencrypted parent beneath it is expected, not a failure.
func encryption(s System, g map[string]*device, id string, seen map[string]bool) (string, string) {
	if seen[id] || len(seen) > 32 {
		return "unknown", "storage_cycle_or_depth"
	}
	d := g[id]
	if d == nil {
		return "unknown", "unresolved_device"
	}
	seen[id] = true
	defer delete(seen, id)
	if d.Type == "crypt" {
		b, e := s.Read("/sys/dev/block/" + id + "/dm/uuid")
		u := strings.TrimSpace(string(b))
		if e == nil && (strings.HasPrefix(u, "CRYPT-LUKS1-") || strings.HasPrefix(u, "CRYPT-LUKS2-")) {
			return "true", "active_luks_mapping"
		}
		return "unknown", "crypt_mapping_cipher_unverified"
	}
	if d.Type == "loop" {
		return "unknown", "loop_backing_file_unresolved"
	}
	if strings.HasPrefix(filepath.Base(d.KName), "zram") {
		return "not_applicable", "memory_backed_device"
	}
	if len(d.Parents) == 0 {
		if d.Type == "disk" || d.Type == "part" {
			return "false", "no_guest_block_encryption"
		}
		return "unknown", "unrecognised_storage_layer"
	}
	result := "true"
	reason := "all_backing_paths_encrypted"
	for p := range d.Parents {
		v, _ := encryption(s, g, p, seen)
		if v == "false" {
			return "false", "unencrypted_backing_path"
		}
		if v != "true" {
			result = "unknown"
			reason = "unresolved_backing_path"
		}
	}
	return result, reason
}
func mountEncryption(s System, g map[string]*device, m mount) Observation {
	o := observation("disk_encryption", "linux_block", m.Target)
	o.Facts["filesystem"] = m.FSType
	o.Facts["coverage"] = "guest_block_layer"
	if m.Target == "/boot" || m.Target == "/boot/efi" || m.Target == "/efi" {
		o.Status = "not_applicable"
		o.Reason = "boot_partition_excluded"
		return o
	}
	if !devNumber.MatchString(m.Dev) {
		return failed(o, "unresolved_mount_device")
	}
	ids := []string{m.Dev}
	if m.FSType == "btrfs" {
		d := g[m.Dev]
		if d == nil || !fsUUID.MatchString(d.UUID) {
			return failed(o, "btrfs_device_set_unresolved")
		}
		paths, e := s.Glob("/sys/fs/btrfs/" + d.UUID + "/devices/*/dev")
		if e != nil || len(paths) == 0 {
			return failed(o, "btrfs_device_set_unresolved")
		}
		ids = nil
		for _, p := range paths {
			b, e := s.Read(p)
			id := strings.TrimSpace(string(b))
			if e != nil || !devNumber.MatchString(id) {
				return failed(o, "btrfs_device_set_unresolved")
			}
			ids = append(ids, id)
		}
	}
	value := "true"
	reason := "all_backing_paths_encrypted"
	for _, id := range ids {
		v, r := encryption(s, g, id, map[string]bool{})
		if v == "false" {
			value = v
			reason = r
			break
		}
		if v != "true" {
			value = v
			reason = r
		}
	}
	o.Reason = reason
	switch value {
	case "true", "false":
		o.Status = "observed"
		o.Facts["encrypted"] = value
	case "not_applicable":
		o.Status = "not_applicable"
	}
	return o
}
func readMounts(ctx context.Context, s System, args ...string) ([]mount, error) {
	a := []string{"--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,MAJ:MIN"}
	a = append(a, args...)
	b, e := s.Run(ctx, "findmnt", a...)
	if e != nil {
		return nil, e
	}
	var result struct {
		Mounts []mount `json:"filesystems"`
	}
	e = json.Unmarshal(b, &result)
	return result.Mounts, e
}
func Disks(ctx context.Context, s System) []Observation {
	summary := observation("disk_encryption", "linux_block", "inventory")
	b, e := s.Run(ctx, "lsblk", "--json", "--paths", "--output", "NAME,KNAME,TYPE,FSTYPE,UUID,MAJ:MIN")
	if e != nil {
		return []Observation{failed(summary, "block_inventory_unavailable")}
	}
	var tree struct {
		Devices []block `json:"blockdevices"`
	}
	if json.Unmarshal(b, &tree) != nil || len(tree.Devices) == 0 {
		return []Observation{failed(summary, "invalid_block_inventory")}
	}
	graph := blockGraph(tree.Devices)
	mounts, e := readMounts(ctx, s)
	if e != nil || len(mounts) == 0 {
		return []Observation{failed(summary, "mount_inventory_unavailable")}
	}
	var out []Observation
	seen := map[string]bool{}
	rootSeen := false
	for _, m := range mounts {
		if m.Target == "/" {
			rootSeen = true
		}
		_, known := graph[m.Dev]
		if !known && m.Target != "/" && m.Target != "/home" && m.FSType != "zfs" {
			continue
		}
		key := m.Dev + ":" + m.Target
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(out) >= 64 {
			out = append(out, failed(summary, "mount_inventory_truncated"))
			break
		}
		if m.FSType == "zfs" {
			out = append(out, zfsEncryption(ctx, s, m))
		} else {
			out = append(out, mountEncryption(s, graph, m))
		}
	}
	if !rootSeen {
		out = append(out, failed(observation("disk_encryption", "linux_block", "/"), "root_mount_missing"))
	}
	swaps, e := s.Read("/proc/swaps")
	if e != nil {
		out = append(out, failed(observation("disk_encryption", "linux_block", "swap"), "swap_inventory_unavailable"))
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(swaps)), "\n")
	if len(lines) == 1 {
		o := observation("disk_encryption", "linux_block", "swap")
		o.Status = "not_applicable"
		o.Reason = "no_active_swap"
		out = append(out, o)
	}
	for i, line := range lines[1:] {
		if i >= 32 {
			out = append(out, failed(summary, "swap_inventory_truncated"))
			break
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			out = append(out, failed(summary, "invalid_swap_inventory"))
			continue
		}
		path := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(f[0])
		o := observation("disk_encryption", "linux_block", fmt.Sprintf("swap:%s", path))
		if len(o.Scope) > 512 {
			o.Scope = "swap:long_path"
			out = append(out, failed(o, "swap_path_too_long"))
			continue
		}
		if f[1] == "file" {
			ms, e := readMounts(ctx, s, "--target", path)
			if e != nil || len(ms) != 1 {
				out = append(out, failed(o, "swapfile_mount_unresolved"))
				continue
			}
			if ms[0].FSType == "zfs" {
				o = zfsEncryption(ctx, s, ms[0])
			} else {
				o = mountEncryption(s, graph, ms[0])
			}
			o.Scope = "swap:" + path
		} else {
			found := ""
			for id, d := range graph {
				if d.Name == path || d.KName == path {
					found = id
					break
				}
			}
			if found == "" {
				o.Reason = "swap_device_unresolved"
			} else {
				v, r := encryption(s, graph, found, map[string]bool{})
				o.Reason = r
				if v == "true" || v == "false" {
					o.Status = "observed"
					o.Facts["encrypted"] = v
				} else if v == "not_applicable" {
					o.Status = "not_applicable"
				}
			}
		}
		o.Facts["coverage"] = "active_swap"
		out = append(out, o)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

var datasetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,255}$`)

func zfsEncryption(ctx context.Context, s System, m mount) Observation {
	o := observation("disk_encryption", "zfs", m.Target)
	o.Facts["coverage"] = "dataset_native_encryption"
	if !datasetName.MatchString(m.Source) {
		return failed(o, "invalid_or_unresolved_dataset")
	}
	b, e := query(ctx, s, "zfs", "get", "-H", "-p", "-o", "property,value", "encryption,encryptionroot,keystatus", m.Source)
	if e != nil {
		return failed(o, "dataset_encryption_unavailable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(b, "\n") {
		f := strings.SplitN(line, "\t", 2)
		if len(f) == 2 {
			fields[f[0]] = f[1]
		}
	}
	switch fields["encryption"] {
	case "aes-128-ccm", "aes-192-ccm", "aes-256-ccm", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
		o.Status = "observed"
		o.Reason = "native_dataset_encryption"
		o.Facts["encrypted"] = "true"
		o.Facts["algorithm"] = fields["encryption"]
	case "off":
		o.Status = "unknown"
		o.Reason = "native_encryption_off_pool_block_encryption_unresolved"
		o.Facts["native_encryption_enabled"] = "false"
	default:
		return failed(o, "unrecognised_zfs_encryption")
	}
	if v := fields["keystatus"]; v == "available" || v == "unavailable" || v == "none" {
		o.Facts["key_status"] = v
	}
	return o
}
