package main

import (
	"fmt"
	"net/netip"
	"strings"
)

type FieldFilter struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

func validateFilters(filters []FieldFilter) error {
	if len(filters) > 32 {
		return fmt.Errorf("at most 32 structured filters per include/exclude list")
	}
	for _, f := range filters {
		if len(f.Field) == 0 || len(f.Field) > 256 || len(f.Value) > 4096 {
			return fmt.Errorf("invalid structured filter field or value length")
		}
		switch f.Operator {
		case "equals", "starts_with", "contains", "exists":
		case "in_cidr":
			prefix, err := netip.ParsePrefix(f.Value)
			if err != nil || prefix.Addr().Zone() != "" {
				return fmt.Errorf("invalid CIDR in structured filter")
			}
		default:
			return fmt.Errorf("unsupported structured filter operator: %s", f.Operator)
		}
	}
	return nil
}
func fieldFilterMatches(e Event, f FieldFilter) bool {
	value, ok := e.Fields[f.Field]
	if !ok {
		return false
	}
	switch f.Operator {
	case "exists":
		return true
	case "equals":
		return value == f.Value
	case "starts_with":
		return strings.HasPrefix(value, f.Value)
	case "contains":
		return strings.Contains(value, f.Value)
	case "in_cidr":
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return false
		}
		prefix, err := netip.ParsePrefix(f.Value)
		return err == nil && prefix.Contains(addr)
	}
	return false
}
func keepStructured(s Source, e Event) bool {
	if len(s.IncludeWhen) > 0 {
		included := false
		for _, f := range s.IncludeWhen {
			if fieldFilterMatches(e, f) {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}
	if len(s.ExcludeWhen) > 0 {
		matched := 0
		for _, f := range s.ExcludeWhen {
			if fieldFilterMatches(e, f) {
				matched++
			}
		}
		if s.ExcludeMatch == "all" {
			if matched == len(s.ExcludeWhen) {
				return false
			}
		} else if matched > 0 {
			return false
		}
	}
	return true
}

type filterTally struct {
	source string
	count  int64
}

func (sp *Spool) addFiltered(s Source, events []Event, key string, state any) error {
	kept := make([]Event, 0, len(events))
	var discarded int64
	for _, e := range events {
		if keepStructured(s, e) {
			kept = append(kept, e)
		} else {
			discarded++
		}
	}
	return sp.add(kept, key, state, filterTally{s.Name, discarded})
}
