package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	return p.Deliver(ctx, c, p.NewReport(all, false))
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
	command := flag.String("command", "report", "report, otlp, once, run, or service (Windows)")
	config := flag.String("config", "", "absolute protected JSON config path (delivery only)")
	diagnostics := flag.Bool("diagnostics", false, "include unavailable probes in local report")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var e error
	switch *command {
	case "report", "otlp":
		var all []p.Observation
		all, e = p.Collect(ctx, p.LocalRunner{})
		if e == nil {
			r := p.NewReport(all, *diagnostics)
			if *command == "otlp" {
				var b []byte
				b, e = p.Payload(r)
				if e == nil {
					_, e = os.Stdout.Write(append(b, '\n'))
				}
			} else {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				e = enc.Encode(r)
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
