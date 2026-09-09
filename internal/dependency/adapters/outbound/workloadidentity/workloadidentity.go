// Package workloadidentity implements the workload-internal authentication
// contract of the dependency authority lane controllers: short-lived access
// tokens are obtained at runtime from the identity attached to the workload
// through the provider instance metadata mechanism. Credentials are never
// injected through the environment, parameters, image content, mounts, or the
// control plane; they live in process memory only, are cached until their
// expiry minus a safety skew, and are refreshed under a single-flight guard.
// Outside the provider runtime the source fails closed.
package workloadidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// gcpMetadataTokenURL is the canonical token endpoint of the GCP instance
	// metadata mechanism; it serves the identity attached to the workload and
	// is reachable only from inside the provider runtime.
	gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	// gcpCloudPlatformScope is the minimal OAuth scope the lane controllers
	// request for the trust-zone API surfaces.
	gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

	// metadataHost is the provider-internal link-local metadata plane; it is
	// the only plain-HTTP endpoint the source accepts besides loopback test
	// servers.
	metadataHost = "metadata.google.internal"
	// expirySkew is the safety margin subtracted from the issued token
	// lifetime before the cached token is considered expired.
	expirySkew = 30 * time.Second
)

// Doer executes HTTP requests. *http.Client satisfies it; tests inject fakes.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Source is the caching, single-flight token source bound to the instance
// metadata mechanism. The zero value is not usable; construct through
// NewGCPSource.
type Source struct {
	endpoint string
	scope    string
	client   Doer
	now      func() time.Time

	mu         sync.Mutex
	token      string
	validUntil time.Time
}

// NewGCPSource binds the canonical GCP instance metadata form with the
// minimal cloud-platform scope. The construction is total: the pinned
// endpoint and scope constants satisfy the source contract, which the package
// tests prove.
func NewGCPSource() *Source {
	source, _ := newSource(gcpMetadataTokenURL, gcpCloudPlatformScope, &http.Client{Timeout: 10 * time.Second}, time.Now)
	return source
}

// newSource constructs a metadata token source and fails closed on an invalid
// endpoint, a non-TLS transport outside the metadata plane and loopback test
// servers, an empty scope, a nil HTTP client, or a nil clock.
func newSource(endpoint string, scope string, client Doer, now func() time.Time) (*Source, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("metadata token endpoint must not be empty")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse metadata token endpoint: %w", err)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("metadata token endpoint %q must carry a host", endpoint)
	}
	if base.Scheme != "https" && !isMetadataPlaneHTTP(base) && !isLoopbackHTTP(base) {
		return nil, fmt.Errorf("metadata token endpoint %q must use https", endpoint)
	}
	if strings.TrimSpace(scope) == "" {
		return nil, errors.New("metadata token scope must not be empty")
	}
	if client == nil {
		return nil, errors.New("http client must not be nil")
	}
	if now == nil {
		return nil, errors.New("clock must not be nil")
	}
	return &Source{endpoint: endpoint, scope: scope, client: client, now: now}, nil
}

// Token returns a valid short-lived token. The cached token is served until
// its issued expiry minus the safety skew; past that point exactly one
// refresh is in flight while concurrent callers wait for its result. A failed
// fetch never poisons the cache: the next call retries the metadata plane.
// Outside the provider runtime the fetch fails closed.
func (s *Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.validUntil) {
		return s.token, nil
	}
	token, lifetime, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}
	s.token = token
	s.validUntil = s.now().Add(lifetime - expirySkew)
	return s.token, nil
}

// fetch issues one token request against the metadata endpoint and validates
// the response contract fail-closed.
func (s *Source) fetch(ctx context.Context) (string, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?scopes="+url.QueryEscape(s.scope), nil)
	if err != nil {
		return "", 0, fmt.Errorf("build metadata token request: %w", err)
	}
	request.Header.Set("Metadata-Flavor", "Google")

	response, err := s.client.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("fetch metadata token: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("fetch metadata token: unexpected status %s", response.Status)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return "", 0, fmt.Errorf("decode metadata token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", 0, errors.New("metadata token response carries no access token")
	}
	if payload.TokenType != "Bearer" {
		return "", 0, fmt.Errorf("metadata token response carries unsupported token type %q", payload.TokenType)
	}
	lifetime := time.Duration(payload.ExpiresIn) * time.Second
	if lifetime <= expirySkew {
		return "", 0, fmt.Errorf("metadata token lifetime %v does not exceed the safety skew", lifetime)
	}
	return payload.AccessToken, lifetime, nil
}

// isMetadataPlaneHTTP permits plain HTTP only for the provider-internal
// link-local metadata plane.
func isMetadataPlaneHTTP(base *url.URL) bool {
	return base.Scheme == "http" && base.Hostname() == metadataHost
}

// isLoopbackHTTP permits plain HTTP only for loopback test servers.
func isLoopbackHTTP(base *url.URL) bool {
	if base.Scheme != "http" {
		return false
	}
	host := base.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
