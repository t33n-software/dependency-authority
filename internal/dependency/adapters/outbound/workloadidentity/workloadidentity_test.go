package workloadidentity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestSource(t *testing.T, endpoint string, client Doer) *Source {
	t.Helper()
	source, err := newSource(endpoint, gcpCloudPlatformScope, client, time.Now)
	if err != nil {
		t.Fatalf("newSource() error = %v", err)
	}
	return source
}

func TestNewSourceValidatesTheContract(t *testing.T) {
	client := http.DefaultClient
	now := time.Now
	for name, tc := range map[string]struct {
		endpoint string
		scope    string
		client   Doer
		now      func() time.Time
	}{
		"empty endpoint":        {"", "scope", client, now},
		"unparseable endpoint":  {"ht tp://invalid", "scope", client, now},
		"hostless endpoint":     {"https://", "scope", client, now},
		"plain http host":       {"http://example.com/token", "scope", client, now},
		"plain http link-local": {"http://169.254.169.254/token", "scope", client, now},
		"non-http scheme":       {"ftp://metadata.google.internal/token", "scope", client, now},
		"empty scope":           {"https://metadata.example.com/token", " ", client, now},
		"nil client":            {"https://metadata.example.com/token", "scope", nil, now},
		"nil clock":             {"https://metadata.example.com/token", "scope", client, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newSource(tc.endpoint, tc.scope, tc.client, tc.now); err == nil {
				t.Fatal("newSource() error = nil, want contract error")
			}
		})
	}
	for _, endpoint := range []string{
		"https://metadata.example.com/token",
		"http://127.0.0.1:8080/token",
		"http://localhost:8080/token",
		gcpMetadataTokenURL,
	} {
		if _, err := newSource(endpoint, "scope", client, now); err != nil {
			t.Errorf("newSource(%q) error = %v, want success", endpoint, err)
		}
	}
}

func TestNewGCPSourceBindsTheCanonicalForm(t *testing.T) {
	if gcpMetadataTokenURL != "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" {
		t.Fatalf("gcpMetadataTokenURL = %q, want the pinned metadata endpoint", gcpMetadataTokenURL)
	}
	if gcpCloudPlatformScope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("gcpCloudPlatformScope = %q, want the minimal cloud-platform scope", gcpCloudPlatformScope)
	}
	source := NewGCPSource()
	if source.endpoint != gcpMetadataTokenURL || source.scope != gcpCloudPlatformScope {
		t.Fatalf("NewGCPSource() bound endpoint %q with scope %q, want the canonical form", source.endpoint, source.scope)
	}
	if source.client == nil || source.now == nil {
		t.Fatal("NewGCPSource() left the client or the clock unbound")
	}
	if _, err := newSource(gcpMetadataTokenURL, gcpCloudPlatformScope, http.DefaultClient, time.Now); err != nil {
		t.Fatalf("newSource(canonical constants) error = %v, want the pinned constants to satisfy the contract", err)
	}
}

func TestTokenFetchesFromTheMetadataEndpoint(t *testing.T) {
	var gotMethod, gotFlavor, gotPath, gotScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotFlavor = r.Header.Get("Metadata-Flavor")
		gotPath = r.URL.Path
		gotScope = r.URL.Query().Get("scopes")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600,"token_type":"Bearer"}`)
	}))
	t.Cleanup(server.Close)

	source := newTestSource(t, server.URL+"/computeMetadata/v1/instance/service-accounts/default/token", server.Client())
	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token != "ya29.test" {
		t.Fatalf("Token() = %q, want the served token", token)
	}
	if gotMethod != http.MethodGet || gotFlavor != "Google" {
		t.Fatalf("request = %s with Metadata-Flavor %q, want GET with the Google flavor header", gotMethod, gotFlavor)
	}
	if !strings.HasSuffix(gotPath, "/instance/service-accounts/default/token") {
		t.Fatalf("request path = %q, want the attached-identity token path", gotPath)
	}
	if gotScope != gcpCloudPlatformScope {
		t.Fatalf("request scope = %q, want the minimal cloud-platform scope", gotScope)
	}
}

func TestTokenCachesUntilTheExpirySkew(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"ya29.call-%d","expires_in":3600,"token_type":"Bearer"}`, call)
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	source, err := newSource(server.URL, gcpCloudPlatformScope, server.Client(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("newSource() error = %v", err)
	}

	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if first != "ya29.call-1" || calls.Load() != 1 {
		t.Fatalf("Token() = %q after %d calls, want the first fetched token after one call", first, calls.Load())
	}

	now = now.Add(3600*time.Second - expirySkew - time.Second)
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if second != first || calls.Load() != 1 {
		t.Fatalf("Token() = %q after %d calls one second before the skew boundary, want the cached token", second, calls.Load())
	}

	now = now.Add(time.Second)
	third, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if third != "ya29.call-2" || calls.Load() != 2 {
		t.Fatalf("Token() = %q after %d calls at the skew boundary, want a refreshed token", third, calls.Load())
	}
}

func TestTokenRefreshIsSingleFlight(t *testing.T) {
	var calls atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"ya29.shared","expires_in":3600,"token_type":"Bearer"}`)
	}))
	t.Cleanup(server.Close)

	source := newTestSource(t, server.URL, server.Client())

	const callers = 32
	var wg sync.WaitGroup
	tokens := make([]string, callers)
	errs := make([]error, callers)
	wg.Add(callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = source.Token(context.Background())
		}()
	}
	<-entered
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("metadata endpoint calls = %d, want exactly one fetch under concurrency", got)
	}
	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("Token() caller %d error = %v", i, errs[i])
		}
		if tokens[i] != "ya29.shared" {
			t.Fatalf("Token() caller %d = %q, want the shared fetched token", i, tokens[i])
		}
	}
}

func TestTokenFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"forbidden status":       {http.StatusForbidden, `{"error":"denied"}`},
		"server error status":    {http.StatusInternalServerError, ``},
		"malformed json":         {http.StatusOK, `{`},
		"missing access token":   {http.StatusOK, `{"expires_in":3600,"token_type":"Bearer"}`},
		"wrong token type":       {http.StatusOK, `{"access_token":"ya29.test","expires_in":3600,"token_type":"MAC"}`},
		"missing expiry":         {http.StatusOK, `{"access_token":"ya29.test","token_type":"Bearer"}`},
		"expiry inside the skew": {http.StatusOK, `{"access_token":"ya29.test","expires_in":10,"token_type":"Bearer"}`},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)
			source := newTestSource(t, server.URL, server.Client())
			if token, err := source.Token(context.Background()); err == nil || token != "" {
				t.Fatalf("Token() = %q, %v, want a fail-closed error without a token", token, err)
			}
		})
	}
}

func TestTokenPropagatesTransportFailure(t *testing.T) {
	source := newTestSource(t, "https://metadata.example.com/token", doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("metadata plane unreachable")
	}))
	if _, err := source.Token(context.Background()); err == nil {
		t.Fatal("Token() error = nil, want the transport failure outside the provider runtime")
	}
}

func TestTokenRetriesAfterAFailureWithoutCachePoisoning(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"ya29.recovered","expires_in":3600,"token_type":"Bearer"}`)
	}))
	t.Cleanup(server.Close)

	source := newTestSource(t, server.URL, server.Client())
	if _, err := source.Token(context.Background()); err == nil {
		t.Fatal("Token() error = nil, want the first fetch to fail")
	}
	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() retry error = %v, want recovery", err)
	}
	if token != "ya29.recovered" {
		t.Fatalf("Token() = %q, want the recovered token", token)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("metadata endpoint calls = %d, want the failure retried", got)
	}
}

func TestTokenCarriesTheCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := newTestSource(t, "https://metadata.example.com/token", doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context().Err() == nil {
			return nil, errors.New("context not propagated")
		}
		return nil, req.Context().Err()
	}))
	if _, err := source.Token(ctx); err == nil {
		t.Fatal("Token() error = nil, want the context error")
	}
}

func TestTokenRejectsANilContext(t *testing.T) {
	var nilContext context.Context
	source := newTestSource(t, "https://metadata.example.com/token", http.DefaultClient)
	if _, err := source.Token(nilContext); err == nil {
		t.Fatal("Token( nil context ) error = nil, want the request build error")
	}
}
