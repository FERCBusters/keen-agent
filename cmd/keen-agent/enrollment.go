package main

import (
	"errors"
	"net/http"
	"os"

	"keen-agent/internal/agentauth"
)

func identityStore(c Config) agentauth.FileStore { return agentauth.FileStore{Dir: c.StateDir} }

// credentialReader returns the configured enrolment code or bootstrap key.
// It is read only when needed and never logged.
func credentialReader(c Config) func() (string, error) {
	return func() (string, error) {
		path := c.Enrollment.CodeFile
		if path == "" {
			path = c.Enrollment.BootstrapKeyFile
		}
		if path == "" {
			return "", errors.New("not enrolled and no enrollment.code_file configured")
		}
		b, err := readPrivate(path, 4096, true)
		if err != nil {
			return "", err
		}
		return agentauth.ReadCredential(b)
	}
}

// openManager loads the private identity, or starts one for first enrolment.
// A missing identity beside a used evidence chain means the state directory
// was partly restored; continuing would hide that, so it stops instead.
func openManager(c Config, sp *Spool, h *http.Client) (*agentauth.Manager, error) {
	store := identityStore(c)
	if _, err := store.Load(); os.IsNotExist(err) && sp != nil && sp.chainPosition() > 0 {
		return nil, errors.New("private identity is missing for an agent that has sent evidence; restore its state directory or purge it and re-enrol")
	}
	id, err := agentauth.Open(store, c.Endpoint, c.Enrollment.Name)
	if err != nil {
		return nil, err
	}
	return agentauth.NewManager(store, id, h, "keen-agent/"+version, credentialReader(c)), nil
}

// checkCredentialConfig validates an existing identity, or the credential
// that will enrol a new one.
func checkCredentialConfig(c Config) error {
	id, err := identityStore(c).Load()
	if err == nil {
		if id.Endpoint != c.Endpoint {
			return errors.New("identity belongs to a different KEEN endpoint")
		}
		return id.Validate()
	}
	if !os.IsNotExist(err) {
		return err
	}
	_, err = credentialReader(c)()
	return err
}

func persistenceFailure(err error) bool {
	var target agentauth.PersistenceError
	return errors.As(err, &target)
}
