package main

import (
    "bytes"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    randomdelay "math/rand/v2"
    bolt "go.etcd.io/bbolt"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "syscall"
    "time"
)

const identityFile = "identity.json"
var agentTokenPattern = regexp.MustCompile(`^ka_([a-f0-9-]{36})\.[A-Za-z0-9_-]{43}$`)
var bootstrapPattern = regexp.MustCompile(`^ke_([a-f0-9-]{36})\.[A-Za-z0-9_-]{43}$`)
var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// This entire record is private. A single fsync+rename commits a token and its
// identity/expiry together. Never include the record in logs or health reports.
type agentIdentity struct {
    Endpoint string `json:"endpoint"`
    Name string `json:"name"`
    ProfileID string `json:"profile_id"`
    AgentID string `json:"agent_id,omitempty"`
    Token string `json:"token,omitempty"`
    ExpiresAt time.Time `json:"expires_at,omitempty"`
    RenewAt time.Time `json:"renew_at,omitempty"`
    EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
    RenewalNonce string `json:"renewal_nonce,omitempty"`
    Blocked string `json:"blocked,omitempty"`
    Failures int `json:"failures,omitempty"`
    NextAttempt time.Time `json:"next_attempt,omitempty"`
}

type credentialManager struct {
    config Config
    state agentIdentity
}

func freshNonce() (string, error) {
    var b [32]byte
    if _, err := rand.Read(b[:]); err != nil { return "", errors.New("cannot generate credential nonce") }
    return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func loadIdentity(c Config) (agentIdentity, error) {
    var state agentIdentity
    b, err := readPrivate(filepath.Join(c.StateDir, identityFile), 16384, true)
    if err != nil { return state, err }
    if json.Unmarshal(b, &state) != nil { return state, errors.New("invalid private identity state; restore a backup or contact an administrator") }
    if c.Enrollment == nil || state.Endpoint != c.Endpoint || state.Name != c.Enrollment.Name || state.ProfileID == "" {
        return state, errors.New("identity belongs to a different endpoint, name or enrollment configuration")
    }
    if state.Token != "" {
        match := agentTokenPattern.FindStringSubmatch(state.Token)
        if match == nil || match[1] != state.AgentID || state.ExpiresAt.IsZero() || state.RenewAt.IsZero() {
            return state, errors.New("invalid private identity credential")
        }
    } else if state.AgentID != "" || !noncePattern.MatchString(state.EnrollmentNonce) {
        return state, errors.New("invalid pending enrollment state")
    }
    if state.RenewalNonce != "" && (state.Token == "" || !noncePattern.MatchString(state.RenewalNonce)) {
        return state, errors.New("invalid pending renewal state")
    }
    return state, nil
}

// The spool holds the process lock before any state is written. Directory
// descriptors and O_EXCL prevent following links or overwriting another file.
type identityPersistenceError struct { cause error }
func (e identityPersistenceError) Error() string { return "cannot persist private identity: " + e.cause.Error() }
func (e identityPersistenceError) Unwrap() error { return e.cause }
func persistenceFailure(err error) bool { var target identityPersistenceError; return errors.As(err, &target) }

func saveIdentity(c Config, state agentIdentity) (err error) {
    defer func() { if err != nil { err = identityPersistenceError{err} } }()
    dir, err := openReadFile(c.StateDir)
    if err != nil { return err }
    defer dir.Close()
    st, err := dir.Stat()
    if err != nil || !st.IsDir() || st.Mode().Perm() & 0077 != 0 {
        return errors.New("identity directory must be private (0700)")
    }
    nonce, err := freshNonce(); if err != nil { return err }
    temporary := ".identity-" + nonce
    fd, err := syscall.Openat(int(dir.Fd()), temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
    if err != nil { return err }
    f := os.NewFile(uintptr(fd), temporary)
    defer syscall.Unlinkat(int(dir.Fd()), temporary)
    b, err := json.Marshal(state)
    if err == nil { _, err = f.Write(b) }
    if err == nil { err = f.Sync() }
    closeErr := f.Close()
    if err != nil { return err }; if closeErr != nil { return closeErr }
    if err = syscall.Renameat(int(dir.Fd()), temporary, int(dir.Fd()), identityFile); err != nil { return err }
    return dir.Sync()
}

func newCredentialManager(c Config, sp *Spool) (*credentialManager, error) {
    if c.Enrollment == nil { return nil, nil }
    state, err := loadIdentity(c)
    if err == nil {
        if err = markEnrollment(sp); err != nil { return nil, err }
        return &credentialManager{c, state}, nil
    }
    if !os.IsNotExist(err) { return nil, err }
    var started bool
    if err = sp.db.View(func(tx *bolt.Tx) error { started = len(tx.Bucket(meta).Get([]byte("enrollment_started"))) != 0; return nil }); err != nil { return nil, err }
    if started { return nil, errors.New("private identity is missing for an enrolled agent; restore its state or contact an administrator") }
    key, err := readPrivate(c.Enrollment.BootstrapKeyFile, 4096, true)
    if err != nil { return nil, err }
    match := bootstrapPattern.FindStringSubmatch(strings.TrimSpace(string(key)))
    if match == nil { return nil, errors.New("invalid bootstrap key file") }
    nonce, err := freshNonce(); if err != nil { return nil, err }
    state = agentIdentity{Endpoint:c.Endpoint, Name:c.Enrollment.Name, ProfileID:match[1], EnrollmentNonce:nonce}
    // Persist before making any enrollment request; retries recover this attempt.
    if err = saveIdentity(c, state); err != nil { return nil, err }
    if err = markEnrollment(sp); err != nil { return nil, err }
    return &credentialManager{c, state}, nil
}

func markEnrollment(sp *Spool) error {
    return sp.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(meta).Put([]byte("enrollment_started"), []byte{1}) })
}

func credential(c Config) (string, error) {
    if c.Enrollment != nil {
        state, err := loadIdentity(c)
        if err != nil { return "", err }
        if state.Blocked != "" || state.Token == "" || state.RenewalNonce != "" || !time.Now().Before(state.ExpiresAt) {
            return "", errors.New("enrollment credential unavailable; inspect agent status")
        }
        return state.Token, nil
    }
    b, err := readPrivate(c.TokenFile, 4096, true)
    if err != nil { return "", err }
    value := strings.TrimSpace(string(b))
    if !strings.HasPrefix(value,"ka_") || strings.ContainsAny(value,"\r\n") { return "", errors.New("invalid credential file") }
    return value, nil
}

func (m *credentialManager) block(reason string) error {
    m.state.Blocked = reason
    if err := saveIdentity(m.config, m.state); err != nil { return err }
    return errors.New(reason)
}

func receiverTime(value string) (time.Time, error) {
    if t, err := time.Parse(time.RFC3339Nano, value); err == nil { return t, nil }
    // KEEN serializes naive UTC database timestamps without a suffix.
    return time.Parse("2006-01-02T15:04:05.999999999", value)
}

type credentialResponse struct {
    Token string `json:"token"`
    Agent struct {
        ID string `json:"id"`
        Name string `json:"name"`
        ProfileID string `json:"enrollment_profile_id"`
        ExpiresAt string `json:"expires_at"`
        Enabled bool `json:"enabled"`
    } `json:"agent"`
}

type enrollmentError struct { status int; retry time.Duration }
func (e enrollmentError) Error() string { return fmt.Sprintf("credential request returned HTTP %d", e.status) }

func credentialRequest(c Config, h *http.Client, action, token string, body any) (credentialResponse, error) {
    var result credentialResponse
    encoded, err := json.Marshal(body); if err != nil { return result, err }
    endpoint := strings.TrimSuffix(c.Endpoint, "/v1/otlp/logs") + "/v1/agents/" + action
    request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
    if err != nil { return result, errors.New("invalid enrollment endpoint") }
    request.Header.Set("Authorization", "Bearer " + token)
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("User-Agent", "keen-agent/"+version)
    response, err := h.Do(request)
    if err != nil { return result, errors.New("credential request failed (network/TLS)") }
    defer response.Body.Close()
    if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
        // Do not log response text, request data, credentials or private nonces.
        io.Copy(io.Discard, io.LimitReader(response.Body,65536))
        return result, enrollmentError{response.StatusCode, retryAfter(response.Header.Get("Retry-After"))}
    }
    b, err := io.ReadAll(io.LimitReader(response.Body,65537))
    if err != nil || len(b)>65536 || json.Unmarshal(b,&result)!=nil { return result, errors.New("invalid credential response; retrying the saved request") }
    return result, nil
}

func retryAfter(value string) time.Duration {
    if seconds, err := time.ParseDuration(value+"s"); err == nil { return max(0,min(seconds,time.Hour)) }
    if date, err := http.ParseTime(value); err == nil { return max(0,min(time.Until(date),time.Hour)) }
    return 0
}

// maintain is called before delivery. No payload is sent while a renewal
// response is pending because the receiver may already have rotated the token.
func (m *credentialManager) maintain(h *http.Client, now time.Time) (bool,error) {
    if m.state.Blocked!="" { return false,nil }
    renewing := m.state.Token!=""
    if renewing && m.state.RenewalNonce=="" && !now.Before(m.state.ExpiresAt) {
        return false,m.block("agent credential expired; administrator intervention required")
    }
    if renewing && m.state.RenewalNonce=="" && now.Before(m.state.RenewAt) { return true,nil }
    if now.Before(m.state.NextAttempt) { return false,nil }
    var token, action string
    body := map[string]string{}
    if renewing {
        if m.state.RenewalNonce=="" {
            nonce,err:=freshNonce();if err!=nil{return false,err}
            next:=m.state
            next.RenewalNonce=nonce
            if err=saveIdentity(m.config,next);err!=nil{return false,err}
            m.state=next
        }
        action,token="renew",m.state.Token
        body["nonce"]=m.state.RenewalNonce
    } else {
        b,err:=readPrivate(m.config.Enrollment.BootstrapKeyFile,4096,true)
        if err!=nil{return m.retry(errors.New("bootstrap key file unavailable"),now)}
        token=strings.TrimSpace(string(b))
        match:=bootstrapPattern.FindStringSubmatch(token)
        if match==nil || match[1]!=m.state.ProfileID { return false,m.block("bootstrap key does not match the saved enrollment profile") }
        action="enroll";body["nonce"]=m.state.EnrollmentNonce;body["name"]=m.state.Name
    }
    result,err:=credentialRequest(m.config,h,action,token,body)
    if err==nil {
        expiry,timeErr:=receiverTime(result.Agent.ExpiresAt)
        match:=agentTokenPattern.FindStringSubmatch(result.Token)
        if timeErr!=nil || !expiry.After(now) || match==nil || match[1]!=result.Agent.ID || result.Agent.ProfileID!=m.state.ProfileID || result.Agent.Name!=m.state.Name || !result.Agent.Enabled || (renewing && result.Agent.ID!=m.state.AgentID) {
            err=errors.New("credential response does not match this identity; retrying the saved request")
        } else {
            next:=m.state
            next.AgentID,next.Token,next.ExpiresAt=result.Agent.ID,result.Token,expiry
            next.RenewAt=expiry.Add(-min(24*time.Hour,expiry.Sub(now)/5))
            next.EnrollmentNonce,next.RenewalNonce="",""
            next.Failures=0;next.NextAttempt=time.Time{}
            if err=saveIdentity(m.config,next);err!=nil{return false,err}
            m.state=next
            return true,nil
        }
    }
    return m.retry(err,now)
}

func (m *credentialManager) retry(err error, now time.Time) (bool,error) {
    var failure enrollmentError
    delay:=time.Duration(1<<min(m.state.Failures+1,8))*time.Second + time.Duration(randomdelay.IntN(1000))*time.Millisecond
    if errors.As(err,&failure) {
        if failure.status>=400 && failure.status<500 && failure.status!=408 && failure.status!=429 {
            return false,m.block(fmt.Sprintf("credential request rejected (HTTP %d); administrator intervention required",failure.status))
        }
        delay=max(delay,failure.retry)
    }
    m.state.Failures=min(m.state.Failures+1,8)
    m.state.NextAttempt=now.Add(delay)
    if saveErr:=saveIdentity(m.config,m.state);saveErr!=nil{return false,saveErr}
    return false,err
}

func checkCredentialConfig(c Config) error {
    if c.Enrollment==nil { _,err:=readPrivate(c.TokenFile,4096,true);return err }
    _,err:=loadIdentity(c)
    if err==nil { return nil }
    if !os.IsNotExist(err) { return err }
    b,err:=readPrivate(c.Enrollment.BootstrapKeyFile,4096,true)
    if err!=nil{return err}
    if !bootstrapPattern.MatchString(strings.TrimSpace(string(b))) {return errors.New("invalid bootstrap key file")}
    return nil
}
