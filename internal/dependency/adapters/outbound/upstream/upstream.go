// Package upstream implements the intake.Upstream port: module content digest
// resolution through the controlled Go module proxy boundary of the intake
// trust zone. The adapter speaks the Go module proxy protocol against the
// configured endpoint and never falls back to a public registry or VCS.
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// ErrModuleNotFound marks a module version that the controlled upstream
// boundary does not serve. A missing version fails closed; there is no
// public-registry fallback.
var ErrModuleNotFound = errors.New("module not found at the controlled upstream boundary")

// Doer executes HTTP requests. *http.Client satisfies it; tests inject
// fakes through it.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TokenSource supplies a short-lived bearer token for the upstream endpoint.
// The token never persists beyond the request it authorizes.
type TokenSource func(ctx context.Context) (string, error)

// Proxy is the controlled upstream boundary client.
type Proxy struct {
	base  *url.URL
	doer  Doer
	token TokenSource
}

// NewProxy constructs the upstream proxy client and fails closed on an
// invalid endpoint, a non-TLS transport outside loopback test servers, a nil
// token source, or a nil HTTP client.
func NewProxy(endpoint string, token TokenSource, client Doer) (Proxy, error) {
	if strings.TrimSpace(endpoint) == "" {
		return Proxy{}, errors.New("upstream endpoint must not be empty")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return Proxy{}, fmt.Errorf("parse upstream endpoint: %w", err)
	}
	if base.Host == "" {
		return Proxy{}, fmt.Errorf("upstream endpoint %q must carry a host", endpoint)
	}
	if base.Scheme != "https" && !isLoopbackHTTP(base) {
		return Proxy{}, fmt.Errorf("upstream endpoint %q must use https", endpoint)
	}
	if token == nil {
		return Proxy{}, errors.New("token source must not be nil")
	}
	if client == nil {
		return Proxy{}, errors.New("http client must not be nil")
	}
	return Proxy{base: base, doer: client, token: token}, nil
}

// FetchDigest resolves the sha256 digest of the module archive served by the
// controlled upstream boundary for the requested module version.
func (p Proxy) FetchDigest(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (string, error) {
	if ecosystem != candidate.EcosystemGo {
		return "", fmt.Errorf("go proxy upstream does not serve ecosystem %q", ecosystem)
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("name must not be empty")
	}
	if strings.TrimSpace(version) == "" {
		return "", errors.New("version must not be empty")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.archiveURL(name, version), nil)
	if err != nil {
		return "", fmt.Errorf("build upstream request: %w", err)
	}
	token, err := p.token(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve upstream credential: %w", err)
	}
	if token == "" {
		return "", errors.New("upstream credential must not be empty")
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := p.doer.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch module archive: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		return "", fmt.Errorf("%w: %s %s", ErrModuleNotFound, name, version)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch module archive: unexpected status %s", response.Status)
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, response.Body); err != nil {
		return "", fmt.Errorf("read module archive: %w", err)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// archiveURL builds the Go module proxy archive URL for the module version,
// escaping the module path and version per the GOPROXY protocol.
func (p Proxy) archiveURL(name string, version string) string {
	base := strings.TrimRight(p.base.String(), "/")
	return base + "/" + escapeModulePath(name) + "/@v/" + escapeModulePath(version) + ".zip"
}

// escapeModulePath encodes upper-case letters as '!' followed by the
// lower-case letter, as the Go module proxy protocol requires.
func escapeModulePath(path string) string {
	var escaped strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			escaped.WriteByte('!')
			escaped.WriteRune(r + ('a' - 'A'))
			continue
		}
		escaped.WriteRune(r)
	}
	return escaped.String()
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
