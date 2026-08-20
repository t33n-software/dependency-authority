package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func staticToken(token string) TokenSource {
	return func(context.Context) (string, error) {
		return token, nil
	}
}

func okResponse(body io.ReadCloser) *http.Response {
	return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: body}
}

func TestNewProxyValidatesConfiguration(t *testing.T) {
	client := http.DefaultClient
	if _, err := NewProxy("", staticToken("token"), client); err == nil {
		t.Fatal("NewProxy( empty endpoint ) error = nil, want error")
	}
	if _, err := NewProxy("ht tp://invalid", staticToken("token"), client); err == nil {
		t.Fatal("NewProxy( unparseable endpoint ) error = nil, want error")
	}
	if _, err := NewProxy("https://", staticToken("token"), client); err == nil {
		t.Fatal("NewProxy( hostless endpoint ) error = nil, want error")
	}
	for _, endpoint := range []string{
		"http://example.com",
		"http://192.168.0.10",
		"http://[2001:db8::1]",
		"ftp://example.com",
	} {
		if _, err := NewProxy(endpoint, staticToken("token"), client); err == nil {
			t.Errorf("NewProxy(%q) error = nil, want transport error", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://intake.example.com",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		if _, err := NewProxy(endpoint, staticToken("token"), client); err != nil {
			t.Errorf("NewProxy(%q) error = %v, want success", endpoint, err)
		}
	}
	if _, err := NewProxy("https://intake.example.com", nil, client); err == nil {
		t.Fatal("NewProxy( nil token ) error = nil, want error")
	}
	if _, err := NewProxy("https://intake.example.com", staticToken("token"), nil); err == nil {
		t.Fatal("NewProxy( nil client ) error = nil, want error")
	}
}

func TestFetchDigestRejectsNonGoEcosystem(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", nil)
	for _, ecosystem := range []candidate.Ecosystem{candidate.EcosystemNPM, candidate.EcosystemPython, candidate.Ecosystem("ruby")} {
		if _, err := proxy.FetchDigest(context.Background(), ecosystem, "example.com/mod", "v1.0.0"); err == nil {
			t.Errorf("FetchDigest(%q) error = nil, want ecosystem error", ecosystem)
		}
	}
}

func TestFetchDigestRejectsEmptyIdentity(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", nil)
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, " ", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest( blank name ) error = nil, want error")
	}
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", ""); err == nil {
		t.Fatal("FetchDigest( empty version ) error = nil, want error")
	}
}

func TestFetchDigestRejectsUnbuildableRequest(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", nil)
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "exa\nmple.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest( control character in name ) error = nil, want request build error")
	}
}

func TestFetchDigestPropagatesTokenErrors(t *testing.T) {
	proxy, err := NewProxy("https://intake.example.com", func(context.Context) (string, error) {
		return "", errors.New("credential expired")
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewProxy() error = %v", err)
	}
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want token error")
	}
}

func TestFetchDigestRejectsEmptyToken(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", nil)
	proxy.token = staticToken("")
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want empty token error")
	}
}

func TestFetchDigestPropagatesTransportError(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}))
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want transport error")
	}
}

func TestFetchDigestMapsMissingModule(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			proxy := newTestProxy(t, "https://intake.example.com", doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					Status:     fmt.Sprintf("%d gone", status),
					StatusCode: status,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}))
			_, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
			if !errors.Is(err, ErrModuleNotFound) {
				t.Fatalf("FetchDigest() error = %v, want ErrModuleNotFound", err)
			}
		})
	}
}

func TestFetchDigestRejectsUnexpectedStatus(t *testing.T) {
	proxy := newTestProxy(t, "https://intake.example.com", doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			Status:     "500 Internal Server Error",
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}))
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want status error")
	}
}

func TestFetchDigestPropagatesReadError(t *testing.T) {
	failingBody := io.NopCloser(&failingReader{})
	proxy := newTestProxy(t, "https://intake.example.com", doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(failingBody), nil
	}))
	if _, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want read error")
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("mid-stream failure")
}

func TestFetchDigestComputesArchiveDigest(t *testing.T) {
	content := []byte("module archive bytes")
	want := "sha256:" + hex.EncodeToString(sha256Sum(content))

	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL+"/europe-west3/projects/p/repositories/r", server.Client())
	got, err := proxy.FetchDigest(context.Background(), candidate.EcosystemGo, "Example.com/Mod", "v1.0.0")
	if err != nil {
		t.Fatalf("FetchDigest() error = %v", err)
	}
	if got != want {
		t.Fatalf("FetchDigest() = %q, want %q", got, want)
	}
	if gotPath != "/europe-west3/projects/p/repositories/r/!example.com/!mod/@v/v1.0.0.zip" {
		t.Fatalf("request path = %q, want escaped module archive path", gotPath)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
}

func TestFetchDigestCarriesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proxy := newTestProxy(t, "https://intake.example.com", doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context().Err() == nil {
			return nil, errors.New("context not propagated")
		}
		return nil, req.Context().Err()
	}))
	if _, err := proxy.FetchDigest(ctx, candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("FetchDigest() error = nil, want context error")
	}
}

func TestEscapeModulePath(t *testing.T) {
	for _, tc := range [][2]string{
		{"example.com/mod", "example.com/mod"},
		{"Example.com/Mod", "!example.com/!mod"},
		{"ALLCAPS", "!a!l!l!c!a!p!s"},
		{"v1.0.0", "v1.0.0"},
	} {
		if got := escapeModulePath(tc[0]); got != tc[1] {
			t.Errorf("escapeModulePath(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
}

func newTestProxy(t *testing.T, endpoint string, client Doer) Proxy {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	proxy, err := NewProxy(endpoint, staticToken("token"), client)
	if err != nil {
		t.Fatalf("NewProxy() error = %v", err)
	}
	return proxy
}

func sha256Sum(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}
