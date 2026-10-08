package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.5"

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "/etc/keen-agent/config.yaml", "configuration file")
	command := flag.String("command", "run", "run, check, status, purge-queue or version")
	confirmPurge := flag.Bool("confirm-discard", false, "confirm permanent deletion of queued, undelivered events")
	flag.Parse()
	if *command == "version" {
		fmt.Println(version)
		return nil
	}
	c, e := config(*path)
	if e != nil {
		return e
	}
	if *command == "check" {
		_, e = readPrivate(c.TokenFile, 4096, true)
		if e != nil {
			return e
		}
		_, e = client(c)
		if e == nil {
			fmt.Println("Configuration is valid")
		}
		return e
	}
	if *command == "status" {
		b, err := os.ReadFile(c.StateDir + "/status.json")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	sp, e := openSpool(c.StateDir, c.QueueMB*1024*1024)
	if e != nil {
		return e
	}
	defer sp.db.Close()
	if *command == "status" {
		n, b, r := sp.stats()
		fmt.Printf("queued=%d bytes=%d rejected_or_gaps=%d\n", n, b, r)
		return nil
	}
	if *command == "purge-queue" {
		if !*confirmPurge {
			return errors.New("purge-queue requires -confirm-discard; stop the service first")
		}
		n, err := sp.purgeQueue()
		if err != nil {
			return err
		}
		// Do not leave the pre-purge queue count visible in status.
		if err := os.Remove(c.StateDir + "/status.json"); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("Discarded %d queued events; collection checkpoints preserved. Restart the service to refresh status.\n", n)
		return nil
	}
	if *command != "run" {
		return errors.New("unknown command")
	}
	h, e := client(c)
	if e != nil {
		return e
	}
	defer h.CloseIdleConnections()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	nextSend := time.Time{}
	started := time.Now()
	var delivered, deliveredBatches int64
	var lastDelivery time.Time
	nextReport := time.Now().Add(time.Minute)
	failures := 0
	blocked := false
	status := map[string]string{}
	nextCollect := time.Time{}
	nextExpire := time.Time{}
	nextHealth := time.Time{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if time.Now().After(nextExpire) {
			nextExpire = time.Now().Add(time.Minute)
			if e = sp.expire(c.RetentionDays); e != nil {
				return e
			}
		}
		if time.Now().After(nextCollect) {
			nextCollect = time.Now().Add(time.Duration(c.PollSeconds) * time.Second)
			for _, source := range c.Sources {
				err := collect(c, source, sp)
				message := "healthy"
				if err != nil {
					message = err.Error()
					if len(message) > 256 {
						message = message[:256]
					}
				}
				if status[source.Name] != message {
					log.Printf("source=%s status=%s", source.Name, message)
				}
				status[source.Name] = message
			}
		}
		drain := false
		if !blocked && time.Now().After(nextSend) {
			before, _, _ := sp.stats()
			e = send(c, sp, h)
			if e == nil {
				failures = 0
				after, _, _ := sp.stats()
				if before > after {
					delivered += before - after
					deliveredBatches++
					lastDelivery = time.Now().UTC()
					drain = after > 0
				}
				nextSend = time.Now()
				if !drain {
					nextSend = time.Now().Add(time.Second)
				}
			} else {
				failures++
				delay := time.Duration(1<<min(failures, 8)) * time.Second
				delay += time.Duration(rand.IntN(1000)) * time.Millisecond
				var de deliveryError
				if errors.As(e, &de) {
					delay = max(delay, de.retry)
					if de.status >= 400 && de.status < 500 && de.status != 408 && de.status != 429 {
						blocked = true
					}
				}
				if strings.Contains(e.Error(), "partial success") {
					blocked = true
				}
				nextSend = time.Now().Add(delay)
				log.Printf("delivery: %s; retry_in=%s blocked=%t", e, delay, blocked)
			}
		}
		n, b, r := sp.stats()
		health := map[string]any{"version": version, "queued": n, "queue_bytes": b, "rejected": r, "sources": status, "delivery_blocked": blocked, "updated_at": time.Now().UTC()}
		health["filtered_by_source"] = sp.filteredStats(c.Sources)
		health["delivered_since_start"] = delivered
		health["delivery_batches_since_start"] = deliveredBatches
		health["delivery_events_per_second_since_start"] = float64(delivered) / time.Since(started).Seconds()
		if !lastDelivery.IsZero() {
			health["last_delivery_at"] = lastDelivery
		}
		if time.Now().After(nextReport) {
			log.Printf("delivery progress: delivered=%d batches=%d queued=%d bytes=%d", delivered, deliveredBatches, n, b)
			nextReport = time.Now().Add(time.Minute)
		}
		if time.Now().After(nextHealth) {
			nextHealth = time.Now().Add(time.Minute)
			if err := heartbeat(c, h, health); err != nil {
				log.Printf("health: %s", err)
			}
		}
		encoded, _ := json.MarshalIndent(health, "", "  ")
		tmp := c.StateDir + "/status.json.tmp"
		if e = os.WriteFile(tmp, encoded, 0600); e != nil {
			return e
		}
		if e = os.Rename(tmp, c.StateDir+"/status.json"); e != nil {
			return e
		}
		if drain {
			select {
			case <-signals:
				return nil
			default:
			}
			continue
		}
		select {
		case <-signals:
			return nil
		case <-ticker.C:
		}
	}
}
