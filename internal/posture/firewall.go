package posture

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

func Firewalls(ctx context.Context, s System) []Observation {
	var out []Observation
	o := observation("firewall", "ufw", "host")
	b, e := query(ctx, s, "ufw", "status", "verbose")
	if e == nil {
		o.Status = "observed"
		o.Reason = "runtime_status_queried"
		switch {
		case strings.HasPrefix(b, "Status: active"):
			o.Facts["manager_active"] = "true"
		case strings.HasPrefix(b, "Status: inactive"):
			o.Facts["manager_active"] = "false"
		default:
			o = failed(o, "unrecognised_ufw_output")
		}
		for _, line := range strings.Split(b, "\n") {
			if strings.HasPrefix(line, "Default:") {
				o.Facts["defaults"] = strings.TrimSpace(strings.TrimPrefix(line, "Default:"))
			}
		}
	} else {
		o.Reason = FailureReason(e)
	}
	out = append(out, o)
	o = observation("firewall", "firewalld", "host")
	state := unit(ctx, s, "firewalld.service")
	if state != nil && state["LoadState"] == "loaded" {
		o.Status = "observed"
		o.Reason = "manager_state_only"
		o.Facts["manager_active"] = strconv.FormatBool(state["ActiveState"] == "active")
		if state["ActiveState"] == "active" {
			zones, e := query(ctx, s, "firewall-cmd", "--get-active-zones")
			def, de := query(ctx, s, "firewall-cmd", "--get-default-zone")
			if e == nil && de == nil && len(zones) <= 1024 && len(def) <= 128 {
				o.Facts["active_zones"] = zones
				o.Facts["default_zone"] = def
				o.Reason = "runtime_zones_queried"
			} else {
				o.Reason = "runtime_zones_unavailable"
			}
			// No zone names from output are interpolated into another command.
			all, ae := query(ctx, s, "firewall-cmd", "--list-all-zones")
			if ae == nil {
				trusted := 0
				for _, l := range strings.Split(all, "\n") {
					if strings.TrimSpace(l) == "target: ACCEPT" {
						trusted++
					}
				}
				o.Facts["accept_target_zone_count"] = strconv.Itoa(trusted)
			}
		}
	} else {
		o.Reason = "firewalld_not_loaded_or_query_denied"
	}
	out = append(out, o)
	o = observation("firewall", "nftables", "host")
	raw, e := s.Run(ctx, "nft", "--json", "list", "ruleset")
	if e == nil {
		o = inspectNFT(raw)
	} else {
		o.Reason = FailureReason(e)
	}
	out = append(out, o)
	// Legacy iptables can coexist with nftables. Observe both families separately.
	for _, name := range []string{"iptables-save", "ip6tables-save"} {
		provider := "iptables"
		if name == "ip6tables-save" {
			provider = "ip6tables"
		}
		o = observation("firewall", provider, "host")
		raw, e := query(ctx, s, name, "-t", "filter")
		if e != nil {
			o.Reason = FailureReason(e)
			out = append(out, o)
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, ":INPUT ") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					o.Facts["input_policy"] = f[1]
				}
			}
		}
		if o.Facts["input_policy"] != "" {
			o.Status = "observed"
			o.Reason = "input_policy_observed"
			count := 0
			for _, line := range strings.Split(raw, "\n") {
				if strings.HasPrefix(line, "-A INPUT ") {
					count++
				}
			}
			o.Facts["input_rule_count"] = strconv.Itoa(count)
		} else {
			o.Reason = "input_chain_not_found"
		}
		out = append(out, o)
	}
	return out
}
func inspectNFT(raw []byte) Observation {
	o := observation("firewall", "nftables", "host")
	var doc struct {
		Items []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Items == nil {
		return failed(o, "invalid_nftables_output")
	}
	input, drop, rules, forward := 0, 0, 0, 0
	for _, item := range doc.Items {
		if c, ok := item["chain"]; ok {
			var chain struct{ Hook, Policy, Family, Type string }
			if json.Unmarshal(c, &chain) != nil {
				return failed(o, "invalid_nftables_chain")
			}
			if chain.Hook == "input" && (chain.Family == "ip" || chain.Family == "ip6" || chain.Family == "inet") {
				input++
				if chain.Policy == "drop" {
					drop++
				}
			}
			if chain.Hook == "forward" {
				forward++
			}
		}
		if _, ok := item["rule"]; ok {
			rules++
		}
	}
	o.Status = "observed"
	o.Reason = "ruleset_structure_only"
	o.Facts["input_base_chains"] = strconv.Itoa(input)
	o.Facts["input_drop_policy_chains"] = strconv.Itoa(drop)
	o.Facts["forward_base_chains"] = strconv.Itoa(forward)
	o.Facts["total_rules"] = strconv.Itoa(rules)
	o.Facts["effective_protection"] = "not_evaluated"
	return o
}
