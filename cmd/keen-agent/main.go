package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"keen-agent/internal/buildinfo"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"keen-agent/internal/agentauth"
)

var version = buildinfo.Version

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "/etc/keen-agent/config.yaml", "configuration file")
	command := flag.String("command", "run", "run, enroll, check, status, key, retry-credentials, purge-queue, posture-host, posture-session or version")
	confirmPurge := flag.Bool("confirm-discard", false, "confirm permanent deletion of queued, undelivered events")
	diagnostics := flag.Bool("posture-diagnostics", false, "include unavailable providers in posture preview")
	flag.Parse()
	if *command == "posture-host" || *command == "posture-session" {
		return runPosture(*command, *diagnostics)
	}
	if *command == "version" {
		fmt.Println(version)
		return nil
	}
	c, e := config(*path)
	if e != nil {
		return e
	}
	switch *command {
	case "check":
		if e = checkCredentialConfig(c); e != nil {
			return e
		}
		if _, e = client(c); e == nil {
			fmt.Println("Configuration is valid")
		}
		return e
	case "key":
		// The key ID and public key, as a reviewer pins them when checking a
		// verification bundle: ueu_verify_bundle.py --key KEY_ID=PUBLIC_KEY.
		identity, err := identityStore(c).Load()
		if err != nil || !identity.Enrolled() {
			return errors.New("not enrolled")
		}
		private, err := identity.Key()
		if err != nil {
			return err
		}
		public := private.Public().(ed25519.PublicKey)
		fmt.Println(identity.KeyID + "=" + base64.RawURLEncoding.EncodeToString(public))
		return nil
	case "status":
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
	h, e := client(c)
	if e != nil {
		return e
	}
	defer h.CloseIdleConnections()
	manager, e := openManager(c, sp, h)
	if e != nil {
		return e
	}
	switch *command {
	case "enroll":
		if manager.Identity().Enrolled() {
			fmt.Println("Already enrolled as agent " + manager.Identity().AgentID)
			return nil
		}
		ready, err := manager.Ready(context.Background(), time.Now())
		if !ready {
			if err == nil {
				err = errors.New("enrolment did not complete; retry later")
			}
			return err
		}
		fmt.Println("Enrolled as agent " + manager.Identity().AgentID + "; start the service to begin collection")
		return nil
	case "purge-queue":
		if !*confirmPurge {
			return errors.New("purge-queue requires -confirm-discard; stop the service first")
		}
		if id := manager.Identity(); id.Enrolled() {
			if sp.sealer, e = newSealer(c, id); e != nil {
				return e
			}
		}
		d, err := sp.purgeQueue()
		if err != nil {
			return err
		}
		if err = sp.recordDiscard(d); err != nil {
			return err
		}
		// Do not leave the pre-purge queue count visible in status.
		if err := os.Remove(c.StateDir + "/status.json"); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("Discarded %d queued records; KEEN receives a signed record of the discard. Restart the service to refresh status.\n", d.count)
		return nil
	case "retry-credentials":
		if err := manager.Unblock(); err != nil {
			return err
		}
		fmt.Println("Credential retry enabled for the saved identity. Restart the service; revoked or expired keys still need a new enrolment code.")
		return nil
	case "run":
	default:
		return errors.New("unknown command")
	}
	return loop(c, sp, h, manager)
}

func loop(c Config, sp *Spool, h *http.Client, manager *agentauth.Manager) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	var e error
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
		ready, credentialErr := manager.Ready(context.Background(), time.Now())
		if credentialErr != nil {
			if persistenceFailure(credentialErr) {
				return credentialErr
			}
			log.Printf("credentials: %s", credentialErr)
		}
		id := manager.Identity()
		if id.Blocked != "" {
			blocked = true
		}
		if id.Enrolled() && (sp.sealer == nil || sp.sealer.producer.InstanceID != id.AgentID || sp.sealer.ceiling != id.EvidenceCeiling()) {
			if sp.sealer, e = newSealer(c, id); e != nil {
				return e
			}
			upgraded, err := sp.upgradeQueue(c.Sources)
			if err != nil {
				return err
			}
			if upgraded > 0 {
				log.Printf("queue: sealed %d records queued by an earlier agent version", upgraded)
			}
		}
		if sp.sealer != nil && time.Now().After(nextExpire) {
			nextExpire = time.Now().Add(time.Minute)
			d, err := sp.expire(c.RetentionDays)
			if err == nil {
				err = sp.recordDiscard(d)
			}
			if err != nil {
				return err
			}
		}
		// Nothing is collected before enrolment: evidence is sealed with this agent's identity.
		if sp.sealer != nil && time.Now().After(nextCollect) {
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
		if ready && !blocked && time.Now().After(nextSend) {
			before, _, _ := sp.stats()
			e = send(c, sp, h, id)
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
						if de.status == 401 || de.status == 403 {
							if err := manager.Block("agent authentication rejected; administrator intervention required"); persistenceFailure(err) {
								return err
							}
						}
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
		modes, clamped := map[string]string{}, false
		if sp.sealer != nil {
			for _, source := range c.Sources {
				m, limited := sp.sealer.mode(source)
				modes[source.Name] = string(m)
				clamped = clamped || limited
			}
		}
		health := map[string]any{
			"version": version, "queued": n, "queue_bytes": b, "rejected": r, "sources": status,
			"delivery_blocked": blocked || !ready, "updated_at": time.Now().UTC(),
			"filtered_by_source": sp.filteredStats(c.Sources), "not_evidence_by_source": sp.notEvidenceStats(c.Sources),
			"delivered_since_start": delivered, "delivery_batches_since_start": deliveredBatches,
			"delivery_events_per_second_since_start": float64(delivered) / time.Since(started).Seconds(),
			"chain_sequence":                         sp.chainPosition(), "evidence_modes": modes, "evidence_mode_clamped": clamped,
		}
		if !lastDelivery.IsZero() {
			health["last_delivery_at"] = lastDelivery
		}
		if time.Now().After(nextReport) {
			log.Printf("delivery progress: delivered=%d batches=%d queued=%d bytes=%d", delivered, deliveredBatches, n, b)
			nextReport = time.Now().Add(time.Minute)
		}
		if ready && id.Blocked == "" && time.Now().After(nextHealth) {
			nextHealth = time.Now().Add(time.Minute)
			if err := heartbeat(c, h, id, health); err != nil {
				log.Printf("health: %s", err)
				var de deliveryError
				if errors.As(err, &de) && (de.status == 401 || de.status == 403) {
					blocked = true
					if err := manager.Block("agent authentication rejected; administrator intervention required"); persistenceFailure(err) {
						return err
					}
				}
			}
		}
		// Identity diagnostics are local only; the private key is never serialised.
		health["agent_id"] = id.AgentID
		health["key_id"] = id.KeyID
		health["credential_expires_at"] = id.ExpiresAt
		health["credential_blocked_reason"] = id.Blocked
		health["credential_ready"] = ready && id.Blocked == ""
		health["credential_next_attempt"] = id.NextAttempt
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
