package main

import (
    "encoding/json"
    "encoding/pem"
    "errors"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "testing"
    "time"
)

const testProfile = "11111111-1111-4111-8111-111111111111"
const testAgent = "22222222-2222-4222-8222-222222222222"
var testKey = "ke_"+testProfile+"."+strings.Repeat("k",43)
var testToken = "ka_"+testAgent+"."+strings.Repeat("a",43)
var renewedToken = "ka_"+testAgent+"."+strings.Repeat("b",43)

type enrollmentReceiver struct {
    mu sync.Mutex
    enrollmentNonce,renewalNonce string
    enrolls,renewals int
    loseEnrollment,loseRenewal bool
    status int
}

func (r *enrollmentReceiver) ServeHTTP(w http.ResponseWriter, request *http.Request) {
    r.mu.Lock();defer r.mu.Unlock()
    if r.status != 0 { w.Header().Set("Retry-After","30");http.Error(w,"sensitive error deliberately not logged",r.status);return }
    var body map[string]string
    if json.NewDecoder(request.Body).Decode(&body)!=nil || !noncePattern.MatchString(body["nonce"]) { http.Error(w,"bad nonce",400);return }
    token:=testToken
    switch request.URL.Path {
    case "/api/v1/agents/enroll":
        if request.Header.Get("Authorization")!="Bearer "+testKey || body["name"]!="web-01" { http.Error(w,"bad credential",401);return }
        if r.enrollmentNonce!="" && r.enrollmentNonce!=body["nonce"] { http.Error(w,"changed nonce",409);return }
        r.enrolls++;r.enrollmentNonce=body["nonce"]
        if r.loseEnrollment {r.loseEnrollment=false;w.Write([]byte("{"));return}
    case "/api/v1/agents/renew":
        if request.Header.Get("Authorization")!="Bearer "+testToken { http.Error(w,"bad credential",401);return }
        if r.renewalNonce!="" && r.renewalNonce!=body["nonce"] {http.Error(w,"changed nonce",401);return}
        r.renewals++;r.renewalNonce=body["nonce"];token=renewedToken
        if r.loseRenewal {r.loseRenewal=false;w.Write([]byte("{"));return}
    default: http.NotFound(w,request);return
    }
    // Match KEEN's naive-UTC timestamp serialization.
    json.NewEncoder(w).Encode(map[string]any{"token":token,"agent":map[string]any{"id":testAgent,"name":"web-01","enrollment_profile_id":testProfile,"enabled":true,"expires_at":time.Now().UTC().Add(90*24*time.Hour).Format("2006-01-02T15:04:05.999999")}})
}

func enrollmentSetup(t *testing.T, handler http.Handler) (Config,*Spool,*http.Client) {
    t.Helper()
    sp:=testSpool(t)
    dir:=filepath.Dir(sp.db.Path())
    server:=httptest.NewTLSServer(handler);t.Cleanup(server.Close)
    keyFile:=filepath.Join(dir,"bootstrap")
    if err:=os.WriteFile(keyFile,[]byte(testKey),0600);err!=nil{t.Fatal(err)}
    ca:=filepath.Join(dir,"ca.pem")
    if err:=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:server.Certificate().Raw}),0600);err!=nil{t.Fatal(err)}
    c:=Config{Endpoint:server.URL+"/api/v1/otlp/logs",StateDir:dir,CAFile:ca,Enrollment:&EnrollmentConfig{BootstrapKeyFile:keyFile,Name:"web-01"}}
    h,err:=client(c);if err!=nil{t.Fatal(err)};t.Cleanup(h.CloseIdleConnections)
    return c,sp,h
}

func TestEnrollmentLostResponseAndRestart(t *testing.T) {
    receiver:=&enrollmentReceiver{loseEnrollment:true}
    c,sp,h:=enrollmentSetup(t,receiver)
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    nonce:=m.state.EnrollmentNonce
    if ready,err:=m.maintain(h,time.Now());ready || err==nil{t.Fatal("lost response should wait for recovery")}
    m,err=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if m.state.EnrollmentNonce!=nonce{t.Fatal("enrollment attempt changed after restart")}
    if ready,err:=m.maintain(h,time.Now().Add(time.Minute));!ready || err!=nil{t.Fatalf("retry: %v",err)}
    token,err:=credential(c);if err!=nil || token!=testToken{t.Fatal("credential missing",err)}
    info,err:=os.Stat(filepath.Join(c.StateDir,identityFile));if err!=nil || info.Mode().Perm()!=0600{t.Fatal("identity permissions")}
    if m.state.EnrollmentNonce!=""{t.Fatal("initial nonce should be removed after commit")}
    os.Remove(c.Enrollment.BootstrapKeyFile)
    if err:=checkCredentialConfig(c);err!=nil{t.Fatal("enrolled machine still needs bootstrap key",err)}
    m,err=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if ready,err:=m.maintain(h,time.Now());!ready || err!=nil{t.Fatal(err)}
    receiver.mu.Lock();defer receiver.mu.Unlock()
    if receiver.enrolls!=2{t.Fatalf("unexpected enrollments: %d",receiver.enrolls)}
}

func TestRenewalLostResponseKeepsNonceAndPausesDelivery(t *testing.T) {
    receiver:=&enrollmentReceiver{loseRenewal:true}
    c,sp,h:=enrollmentSetup(t,receiver)
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if ready,err:=m.maintain(h,time.Now());!ready || err!=nil{t.Fatal(err)}
    m.state.RenewAt=time.Now().Add(-time.Second)
    if err:=saveIdentity(c,m.state);err!=nil{t.Fatal(err)}
    if ready,err:=m.maintain(h,time.Now());ready || err==nil{t.Fatal("renewal response should be retried")}
    if _,err:=credential(c);err==nil{t.Fatal("pending renewal must stop ingestion with old token")}
    nonce:=m.state.RenewalNonce
    m,err=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if m.state.RenewalNonce!=nonce{t.Fatal("renewal nonce lost")}
    if ready,err:=m.maintain(h,time.Now().Add(time.Minute));!ready || err!=nil{t.Fatal(err)}
    if token,err:=credential(c);err!=nil || token!=renewedToken{t.Fatal("renewed token missing",err)}
    receiver.mu.Lock();defer receiver.mu.Unlock()
    if receiver.enrolls!=1 || receiver.renewals!=2{t.Fatal("unexpected request counts")}
}

func TestEnrollmentRejectionPersistsAndNeverFallsBack(t *testing.T) {
    receiver:=&enrollmentReceiver{status:403}
    c,sp,h:=enrollmentSetup(t,receiver)
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    _,err=m.maintain(h,time.Now());if err==nil || strings.Contains(err.Error(),"sensitive"){t.Fatal("unsafe rejection error",err)}
    m,err=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    receiver.mu.Lock();receiver.status=0;receiver.mu.Unlock()
    if ready,err:=m.maintain(h,time.Now().Add(time.Hour));ready || err!=nil{t.Fatal("blocked attempt retried")}
    if m.state.Blocked==""{t.Fatal("blocked state was lost")}
}

func TestMissingIdentityAndEndpointChangeCannotReenroll(t *testing.T) {
    c,sp,h:=enrollmentSetup(t,&enrollmentReceiver{})
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if ready,err:=m.maintain(h,time.Now());!ready || err!=nil{t.Fatal(err)}
    changed:=c;changed.Endpoint="https://different.example/api/v1/otlp/logs"
    if _,err:=newCredentialManager(changed,sp);err==nil{t.Fatal("identity transferred to another receiver")}
    os.Remove(filepath.Join(c.StateDir,identityFile))
    if _,err:=newCredentialManager(c,sp);err==nil{t.Fatal("missing identity silently reenrolled")}
}

func TestEnrollmentRateLimitAndExpiry(t *testing.T) {
    receiver:=&enrollmentReceiver{status:429}
    c,sp,h:=enrollmentSetup(t,receiver)
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    now:=time.Now()
    if ready,err:=m.maintain(h,now);ready || err==nil{t.Fatal("expected rate limit")}
    if m.state.NextAttempt.Before(now.Add(30*time.Second)) || m.state.Blocked!=""{t.Fatal("rate limit not respected")}
    receiver.mu.Lock();receiver.status=0;receiver.mu.Unlock()
    if ready,err:=m.maintain(h,now.Add(time.Minute));!ready || err!=nil{t.Fatal(err)}
    m.state.ExpiresAt=time.Now().Add(-time.Second);m.state.RenewAt=m.state.ExpiresAt
    if ready,err:=m.maintain(h,time.Now());ready || err==nil{t.Fatal("expired identity must stop")}
    if m.state.Token!=testToken || m.state.EnrollmentNonce!=""{t.Fatal("expired identity reset")}
}

func TestEnrollmentTLSRedirectAndSecretSafety(t *testing.T) {
    c,_,h:=enrollmentSetup(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,"https://attacker.example",302)}))
    _,err:=credentialRequest(c,h,"enroll",testKey,map[string]string{"nonce":strings.Repeat("n",43),"name":"web-01"})
    if err==nil || strings.Contains(err.Error(),testKey){t.Fatal("redirect accepted or secret disclosed")}
    untrusted,err:=client(Config{});if err!=nil{t.Fatal(err)};defer untrusted.CloseIdleConnections()
    if _,err:=credentialRequest(c,untrusted,"enroll",testKey,nil);err==nil{t.Fatal("untrusted TLS accepted")}
}

func TestEnrollmentPersistenceFailureDoesNotLoseNonce(t *testing.T) {
    c,sp,h:=enrollmentSetup(t,&enrollmentReceiver{})
    m,err:=newCredentialManager(c,sp);if err!=nil{t.Fatal(err)}
    if ready,err:=m.maintain(h,time.Now());!ready || err!=nil{t.Fatal(err)}
    m.state.RenewAt=time.Now().Add(-time.Second)
    // A nonprivate directory must fail closed, even when tests run as root.
    os.Chmod(c.StateDir,0755);defer os.Chmod(c.StateDir,0700)
    if ready,err:=m.maintain(h,time.Now());ready || !persistenceFailure(err){t.Fatal("unsafe persistence accepted",err)}
    if m.state.RenewalNonce!=""{t.Fatal("unpersisted renewal nonce escaped into memory")}
}

func TestEnrollmentConfigurationAndManualCredentials(t *testing.T) {
    dir:=t.TempDir()
    path:=filepath.Join(dir,"config.yaml")
    contents:="endpoint: https://keen.example/api/v1/otlp/logs\nstate_dir: "+dir+"\nenrollment:\n  bootstrap_key_file: "+dir+"/key\n  name: web-01\nsources:\n  - name: journal\n    kind: journal\n    parser: syslog\n"
    os.WriteFile(path,[]byte(contents),0600)
    c,err:=config(path);if err!=nil{t.Fatal(err)}
    if c.TokenFile!="" || c.Enrollment.Name!="web-01"{t.Fatal("wrong configuration")}
    os.WriteFile(path,[]byte(contents+"token_file: /etc/keen-agent/token\n"),0600)
    if _,err:=config(path);err==nil{t.Fatal("ambiguous credential modes accepted")}
    manual:=filepath.Join(dir,"manual-token");os.WriteFile(manual,[]byte(testToken),0600)
    if value,err:=credential(Config{TokenFile:manual});err!=nil || value!=testToken{t.Fatal("manual token changed",err)}
    if _,err:=credential(Config{TokenFile:filepath.Join(dir,"missing")});!errors.Is(err,os.ErrNotExist){t.Fatal("missing manual token did not fail",err)}
}
