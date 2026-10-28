package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"keen-agent/internal/agentauth"
	p "keen-agent/internal/nativeposture"
	"os"
	"os/signal"
	"time"
)

func once(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c, e := p.LoadConfig(path)
	if e != nil {
		return e
	}
	all, e := p.Collect(ctx, p.LocalRunner{})
	if e != nil {
		return e
	}
	return p.Deliver(ctx, c, all, time.Now().UTC())
}
func loop(ctx context.Context, path string) error {
	c, e := p.LoadConfig(path)
	if e != nil {
		return e
	}
	for {
		if e = once(ctx, path); e != nil {
			fmt.Fprintln(os.Stderr, "keen-posture:", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(c.IntervalSeconds) * time.Second):
		}
	}
}
func main() {
	command := flag.String("command", "report", "report, preview, enroll, once, run, or service (Windows)")
	config := flag.String("config", "", "absolute protected JSON config path (enrolment and delivery)")
	diagnostics := flag.Bool("diagnostics", false, "include unavailable probes in local report")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var e error
	switch *command {
	case "report", "preview":
		var all []p.Observation
		all, e = p.Collect(ctx, p.LocalRunner{})
		if e == nil && *command == "report" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			e = enc.Encode(p.NewReport(all, *diagnostics))
		} else if e == nil {
			// The envelopes this device would send, with a throwaway pseudonym key.
			var envelopes []map[string]any
			envelopes, e = p.Preview(all)
			if e == nil {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				e = enc.Encode(envelopes)
			}
		}
	case "enroll":
		var c p.Config
		if c, e = p.LoadConfig(*config); e == nil {
			var id agentauth.Identity
			if id, e = p.Enroll(ctx, c); e == nil {
				fmt.Println("Enrolled as agent " + id.AgentID)
			}
		}
	case "once":
		e = once(ctx, *config)
	case "run":
		e = loop(ctx, *config)
	case "service":
		e = service(*config)
	default:
		e = errors.New("unknown command")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "keen-posture:", e)
		os.Exit(1)
	}
}
