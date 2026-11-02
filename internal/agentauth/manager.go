package agentauth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"time"

	"keen-agent/internal/ueu"
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

// Manager keeps an identity enrolled and renewed, and KEEN's encryption key
// current. It sends nothing while a renewal response is pending, because KEEN
// may already have rotated the key.
type Manager struct {
	Store      Store
	Client     *http.Client
	UserAgent  string
	Credential func() (string, error)
	state      Identity
	// refresh is set when KEEN names another encryption key or refuses ours.
	refresh   bool
	lastFetch time.Time
	fetchErr  error
	lastErr   string
}

const (
	// Fetch KEEN's key this long before the current one stops being usable.
	keyRefreshAhead = 7 * 24 * time.Hour
	// At most one fetch a minute when asked to, and one an hour ahead of expiry.
	keyFetchSpacing = time.Minute
	keyAheadSpacing = time.Hour
)

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

// Grant records the event catalogue KEEN granted in a sealed reply.
func (m *Manager) Grant(catalogue ueu.CatalogueRef) error {
	if catalogue == m.state.Catalogue {
		return nil
	}
	next := m.state
	next.Catalogue = catalogue
	return m.save(next)
}

// Unblock clears a block and the retry backoff, keeping any pending attempt.
func (m *Manager) Unblock() error {
	next := m.state
	next.Blocked, next.Failures, next.NextAttempt = "", 0, time.Time{}
	return m.save(next)
}

// Ready enrols or renews when due, keeps KEEN's encryption key current, and
// reports whether evidence may be sent.
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
			if err := m.keepServerKey(ctx, now); err != nil {
				return m.state.Server.Usable(now), err
			}
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
	grant, server, err := Enroll(ctx, m.Client, m.state, credential, m.UserAgent)
	if err == nil {
		next := m.state
		if err = next.Accept(grant, next.PrivateKey, now); err == nil {
			next.Pin(server)
			m.lastErr = ""
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
	if err := m.keepServerKey(ctx, now); err != nil {
		return m.retry(err, now)
	}
	grant, err := m.post(ctx, func(id Identity) (Grant, Response, error) {
		g, err := Renew(ctx, m.Client, id, m.UserAgent)
		return g, Response{}, err
	})
	if err == nil {
		next := m.state
		if err = next.Accept(grant, next.RenewalKey, now); err == nil {
			m.lastErr = ""
			return true, m.save(next)
		}
	}
	return m.retry(err, now)
}

// LastError is the most recent enrolment, renewal or key fetch failure, for
// local status; empty once one succeeds.
func (m *Manager) LastError() string { return m.lastErr }

// retry backs off after a failed enrolment or renewal. A refusal from KEEN
// waits RefusalBackoff: it is unsealed and may not be KEEN's, so it never
// blocks the identity.
func (m *Manager) retry(err error, now time.Time) (bool, error) {
	var rejected HTTPError
	delay := time.Duration(1<<min(m.state.Failures+1, 8))*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond
	if errors.As(err, &rejected) {
		if rejected.Permanent() {
			delay = max(delay, RefusalBackoff)
			advice := "If the code was used, expired or revoked, save a new one"
			if m.state.Enrolled() {
				advice = "If this agent was revoked or its key expired, purge its state directory and enrol again with a new code"
			}
			err = fmt.Errorf("KEEN refused the credential request (HTTP %d); retrying in %s. %s", rejected.Status, RefusalBackoff, advice)
		}
		delay = max(delay, rejected.Retry)
	}
	m.lastErr = err.Error()
	next := m.state
	next.Failures = min(next.Failures+1, 8)
	next.NextAttempt = now.Add(delay)
	if saveErr := m.save(next); saveErr != nil {
		return false, saveErr
	}
	return false, err
}

// keepServerKey fetches KEEN's server-key document when the encryption key
// is missing, near its end, or KEEN has named another one. The document must
// match the identity pinned at enrolment. An error leaves the saved key in
// place; requests continue with it while it is usable.
func (m *Manager) keepServerKey(ctx context.Context, now time.Time) error {
	_, err := m.fetchServerKey(ctx, now)
	return err
}

// fetchServerKey is keepServerKey, also reporting whether it fetched. Fetches
// are spaced (keyFetchSpacing, or keyAheadSpacing ahead of expiry) whatever
// asks for them, so refusals cannot make the agent fetch on every request.
func (m *Manager) fetchServerKey(ctx context.Context, now time.Time) (bool, error) {
	k := m.state.Server
	due := m.refresh || !k.Usable(now)
	spacing := keyFetchSpacing
	if !due && now.Before(k.NotAfter.Add(-keyRefreshAhead)) {
		return false, nil
	}
	if !due {
		spacing = keyAheadSpacing
	}
	if !m.lastFetch.IsZero() && now.Before(m.lastFetch.Add(spacing)) {
		if !k.Usable(now) {
			if m.fetchErr != nil {
				return false, m.fetchErr
			}
			return false, KeyRefreshNeeded{"waiting to fetch KEEN's key again"}
		}
		return false, nil
	}
	m.lastFetch = now
	fetched, err := FetchServerKey(ctx, m.Client, m.state.Endpoint, k.Identity, m.UserAgent, now)
	if err != nil {
		m.fetchErr = fmt.Errorf("KEEN encryption key: %w", err)
		m.lastErr = m.fetchErr.Error()
		return true, m.fetchErr
	}
	if m.fetchErr != nil && m.lastErr == m.fetchErr.Error() {
		m.lastErr = ""
	}
	m.fetchErr = nil
	m.refresh = false
	if fetched == k {
		return true, nil
	}
	next := m.state
	next.Pin(fetched)
	return true, m.save(next)
}

// post runs one request with the current identity. When KEEN no longer
// accepts the encryption key (421) it fetches the key once and retries; when
// a response names another key it fetches it before the next request.
func (m *Manager) post(ctx context.Context, send func(Identity) (Grant, Response, error)) (Grant, error) {
	g, _, err := m.send(ctx, send)
	return g, err
}

func (m *Manager) send(ctx context.Context, send func(Identity) (Grant, Response, error)) (Grant, Response, error) {
	for attempt := 0; ; attempt++ {
		g, res, err := send(m.state)
		if NeedsKeyRefresh(err) && attempt == 0 {
			m.refresh = true
			fetched, ferr := m.fetchServerKey(ctx, time.Now())
			if ferr != nil {
				return g, res, ferr
			}
			if !fetched {
				// Fetched within the minute: report the refusal; the caller
				// backs off and the next attempt fetches.
				return g, res, err
			}
			continue
		}
		if err == nil && res.ServerKey != "" && res.ServerKey != m.state.Server.EncryptionKey {
			m.refresh = true
		}
		return g, res, err
	}
}

// Post sends a request encrypted to KEEN and signed with the current key,
// keeping KEEN's encryption key current as described for send.
func (m *Manager) Post(ctx context.Context, url, operation string, body []byte) (Response, error) {
	_, res, err := m.send(ctx, func(id Identity) (Grant, Response, error) {
		res, err := Post(ctx, m.Client, url, operation, body, id, m.UserAgent)
		return Grant{}, res, err
	})
	return res, err
}
