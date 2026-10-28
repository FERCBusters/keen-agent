package agentauth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"time"
)

// Store persists the private identity atomically.
type Store interface {
	Load() (Identity, error)
	Save(Identity) error
}

// PersistenceError means the identity could not be saved; callers stop.
type PersistenceError struct{ Cause error }

func (e PersistenceError) Error() string {
	return "cannot persist private identity: " + e.Cause.Error()
}
func (e PersistenceError) Unwrap() error { return e.Cause }

// Manager keeps an identity enrolled and renewed. It sends nothing while a
// renewal response is pending, because KEEN may already have rotated the key.
type Manager struct {
	Store      Store
	Client     *http.Client
	UserAgent  string
	Credential func() (string, error)
	state      Identity
}

// Open loads the identity, or starts one for a first enrolment.
func Open(store Store, endpoint, name string) (Identity, error) {
	id, err := store.Load()
	if err == nil {
		if id.Endpoint != endpoint {
			return id, errors.New("identity belongs to a different KEEN endpoint")
		}
		if name != "" && id.Name != "" && id.Name != name {
			return id, errors.New("identity belongs to a different agent name")
		}
		return id, id.Validate()
	}
	if !os.IsNotExist(err) {
		return id, err
	}
	id, err = New(endpoint)
	if err != nil {
		return id, err
	}
	id.Name = name
	if err = store.Save(id); err != nil {
		return id, PersistenceError{err}
	}
	return id, nil
}

// NewManager wraps a loaded identity.
func NewManager(store Store, id Identity, h *http.Client, userAgent string, credential func() (string, error)) *Manager {
	return &Manager{Store: store, Client: h, UserAgent: userAgent, Credential: credential, state: id}
}

// Identity returns the current private identity.
func (m *Manager) Identity() Identity { return m.state }

func (m *Manager) save(next Identity) error {
	if err := m.Store.Save(next); err != nil {
		return PersistenceError{err}
	}
	m.state = next
	return nil
}

// Block stops credential use until an administrator intervenes.
func (m *Manager) Block(reason string) error {
	next := m.state
	next.Blocked = reason
	if err := m.save(next); err != nil {
		return err
	}
	return errors.New(reason)
}

// Unblock clears a block and the retry backoff, keeping any pending attempt.
func (m *Manager) Unblock() error {
	next := m.state
	next.Blocked, next.Failures, next.NextAttempt = "", 0, time.Time{}
	return m.save(next)
}

// Ready enrols or renews when due and reports whether evidence may be sent.
func (m *Manager) Ready(ctx context.Context, now time.Time) (bool, error) {
	s := m.state
	if s.Blocked != "" {
		return false, nil
	}
	if s.Enrolled() && s.RenewalNonce == "" {
		if !now.Before(s.ExpiresAt) {
			return false, m.Block("agent key expired; re-enrol with a new code")
		}
		if now.Before(s.RenewAt) {
			return true, nil
		}
	}
	if now.Before(s.NextAttempt) {
		return s.Enrolled() && s.RenewalNonce == "", nil
	}
	if !s.Enrolled() {
		return m.enroll(ctx, now)
	}
	return m.renew(ctx, now)
}

func (m *Manager) enroll(ctx context.Context, now time.Time) (bool, error) {
	credential, err := m.Credential()
	if err != nil {
		return m.retry(fmt.Errorf("enrolment credential unavailable: %w", err), now)
	}
	if BootstrapPattern.MatchString(credential) {
		profile := BootstrapPattern.FindStringSubmatch(credential)[1]
		if m.state.ProfileID != "" && m.state.ProfileID != profile {
			return false, m.Block("bootstrap key does not match the saved enrolment profile")
		}
		if m.state.EnrollmentNonce == "" {
			next := m.state
			next.ProfileID = profile
			if next.EnrollmentNonce, err = NewSecret(); err != nil {
				return false, err
			}
			// Persist before asking, so a retry after a lost response is recognised.
			if err = m.save(next); err != nil {
				return false, err
			}
		}
	}
	grant, err := Enroll(ctx, m.Client, m.state, credential, m.UserAgent)
	if err == nil {
		next := m.state
		if err = next.Accept(grant, next.PrivateKey, now); err == nil {
			return true, m.save(next)
		}
	}
	return m.retry(err, now)
}

func (m *Manager) renew(ctx context.Context, now time.Time) (bool, error) {
	if m.state.RenewalNonce == "" {
		next := m.state
		var err error
		if next.RenewalNonce, err = NewSecret(); err != nil {
			return false, err
		}
		if next.RenewalKey, err = NewSecret(); err != nil {
			return false, err
		}
		if err = m.save(next); err != nil {
			return false, err
		}
	}
	grant, err := Renew(ctx, m.Client, m.state, m.UserAgent)
	if err == nil {
		next := m.state
		if err = next.Accept(grant, next.RenewalKey, now); err == nil {
			return true, m.save(next)
		}
	}
	return m.retry(err, now)
}

func (m *Manager) retry(err error, now time.Time) (bool, error) {
	var rejected HTTPError
	delay := time.Duration(1<<min(m.state.Failures+1, 8))*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond
	if errors.As(err, &rejected) {
		if rejected.Permanent() {
			return false, m.Block(fmt.Sprintf("KEEN rejected the credential request (HTTP %d); administrator intervention required", rejected.Status))
		}
		delay = max(delay, rejected.Retry)
	}
	next := m.state
	next.Failures = min(next.Failures+1, 8)
	next.NextAttempt = now.Add(delay)
	if saveErr := m.save(next); saveErr != nil {
		return false, saveErr
	}
	return false, err
}
