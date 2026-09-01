package artifactregistry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
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

func newTestClient(t *testing.T, doer Doer) Client {
	t.Helper()
	client, err := NewClient("https://artifactregistry.googleapis.com", staticToken("token"), doer)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func okResponse(body string) *http.Response {
	return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
}

func TestNewClientValidatesConfiguration(t *testing.T) {
	if _, err := NewClient(" ", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewClient( blank endpoint ) error = nil, want error")
	}
	if _, err := NewClient("ht tp://invalid", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewClient( unparseable endpoint ) error = nil, want error")
	}
	if _, err := NewClient("https://", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewClient( hostless endpoint ) error = nil, want error")
	}
	for _, endpoint := range []string{"http://example.com", "http://10.0.0.1", "ftp://example.com"} {
		if _, err := NewClient(endpoint, staticToken("token"), http.DefaultClient); err == nil {
			t.Errorf("NewClient(%q) error = nil, want transport error", endpoint)
		}
	}
	for _, endpoint := range []string{"https://artifactregistry.googleapis.com", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if _, err := NewClient(endpoint, staticToken("token"), http.DefaultClient); err != nil {
			t.Errorf("NewClient(%q) error = %v, want success", endpoint, err)
		}
	}
	if _, err := NewClient("https://artifactregistry.googleapis.com", nil, http.DefaultClient); err == nil {
		t.Fatal("NewClient( nil token ) error = nil, want error")
	}
	if _, err := NewClient("https://artifactregistry.googleapis.com", staticToken("token"), nil); err == nil {
		t.Fatal("NewClient( nil doer ) error = nil, want error")
	}
}

func TestDoPropagatesCredentialFailures(t *testing.T) {
	client, err := NewClient("https://artifactregistry.googleapis.com", func(context.Context) (string, error) {
		return "", errors.New("token exchange failed")
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, _, err := client.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want credential error")
	}

	client.token = staticToken("")
	if _, _, err := client.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want empty credential error")
	}
}

func TestDoPropagatesTransportAndReadFailures(t *testing.T) {
	client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset")
	}))
	if _, _, err := client.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want transport error")
	}

	client = newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: io.NopCloser(&failingReader{})}, nil
	}))
	if _, _, err := client.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want read error")
	}
}

func TestDoRejectsUnbuildableRequests(t *testing.T) {
	client := newTestClient(t, http.DefaultClient)
	if _, _, err := client.do(context.Background(), http.MethodGet, "https://exa\nmple.com", nil, ""); err == nil {
		t.Fatal("do() error = nil, want request build error")
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("mid-stream failure")
}

func TestDoCarriesMethodContentTypeAndCredential(t *testing.T) {
	var gotMethod, gotAuth, gotContentType, gotBody string
	client := newTestClient(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotMethod = req.Method
		gotAuth = req.Header.Get("Authorization")
		gotContentType = req.Header.Get("Content-Type")
		content, _ := io.ReadAll(req.Body)
		gotBody = string(content)
		return okResponse(`{"ok": true}`), nil
	}))
	body, status, err := client.do(context.Background(), http.MethodPost, "https://artifactregistry.googleapis.com/v1/x", []byte("payload"), "application/json")
	if err != nil {
		t.Fatalf("do() error = %v", err)
	}
	if status != http.StatusOK || string(body) != `{"ok": true}` {
		t.Fatalf("do() = %q, %d, want ok payload", body, status)
	}
	if gotMethod != http.MethodPost || gotAuth != "Bearer token" || gotContentType != "application/json" || gotBody != "payload" {
		t.Fatalf("request = %q %q %q %q, want POST with bearer and JSON content", gotMethod, gotAuth, gotContentType, gotBody)
	}
}

func TestUploadOutcomes(t *testing.T) {
	t.Run("created", func(t *testing.T) {
		var gotURL, gotBody, gotContentType string
		client := newTestClient(t, doerFunc(func(req *http.Request) (*http.Response, error) {
			gotURL = req.URL.String()
			content, _ := io.ReadAll(req.Body)
			gotBody = string(content)
			gotContentType = req.Header.Get("Content-Type")
			return okResponse(`{"operation": {"name": "operations/1"}}`), nil
		}))
		err := client.upload(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1", "file.json", []byte(`{"doc":true}`))
		if err != nil {
			t.Fatalf("upload() error = %v", err)
		}
		if gotURL != "https://artifactregistry.googleapis.com/upload/v1/projects/p/locations/l/repositories/r/genericArtifacts:create" {
			t.Fatalf("upload URL = %q, want genericArtifacts:create", gotURL)
		}
		if !strings.HasPrefix(gotContentType, "multipart/") {
			t.Fatalf("content type = %q, want multipart", gotContentType)
		}
		for _, part := range []string{`{"filename":"file.json","package_id":"pkg","version_id":"v1"}`, `{"doc":true}`} {
			if !strings.Contains(gotBody, part) {
				t.Fatalf("upload body misses %q", part)
			}
		}
	})

	t.Run("conflict is idempotent", func(t *testing.T) {
		client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{Status: "409 Conflict", StatusCode: http.StatusConflict, Body: io.NopCloser(strings.NewReader(""))}, nil
		}))
		if err := client.upload(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1", "file.json", []byte("{}")); err != nil {
			t.Fatalf("upload() error = %v, want idempotent success", err)
		}
	})

	t.Run("status error", func(t *testing.T) {
		client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
		}))
		if err := client.upload(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1", "file.json", []byte("{}")); err == nil {
			t.Fatal("upload() error = nil, want status error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("reset")
		}))
		if err := client.upload(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1", "file.json", []byte("{}")); err == nil {
			t.Fatal("upload() error = nil, want transport error")
		}
	})
}

func TestListPaginatesAndFiltersByOwner(t *testing.T) {
	requests := make([]string, 0)
	client := newTestClient(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if strings.Contains(req.URL.RawQuery, "pageToken=two") {
			return okResponse(`{"files": [
				{"name": "projects/p/locations/l/repositories/r/files/pkg:v1:b.json", "owner": "projects/p/locations/l/repositories/r/packages/pkg/versions/v1", "createTime": "2026-08-20T10:00:01Z"},
				{"name": "projects/p/locations/l/repositories/r/files/other:v1:c.json", "owner": "projects/p/locations/l/repositories/r/packages/other/versions/v1", "createTime": "2026-08-20T10:00:02Z"}
			]}`), nil
		}
		return okResponse(`{"files": [
			{"name": "projects/p/locations/l/repositories/r/files/pkg:v1:a.json", "owner": "projects/p/locations/l/repositories/r/packages/pkg/versions/v1", "createTime": "2026-08-20T10:00:00Z"}
		], "nextPageToken": "two"}`), nil
	}))

	files, err := client.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1")
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if len(files) != 2 || files[0].Name != "projects/p/locations/l/repositories/r/files/pkg:v1:a.json" || files[1].Name != "projects/p/locations/l/repositories/r/files/pkg:v1:b.json" {
		t.Fatalf("list() = %v, want the two owned files", files)
	}
	if len(requests) != 2 || !strings.Contains(requests[0], "pageSize=1000") || !strings.Contains(requests[1], "pageToken=two") {
		t.Fatalf("list requests = %v, want paginated sequence", requests)
	}
}

func TestListFailures(t *testing.T) {
	client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "403 Forbidden", StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := client.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want status error")
	}

	client = newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{`), nil
	}))
	if _, err := client.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want decode error")
	}

	client = newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := client.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want transport error")
	}
}

func TestDownload(t *testing.T) {
	client := newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse("file-content"), nil
	}))
	content, err := client.download(context.Background(), "projects/p/locations/l/repositories/r/files/pkg:v1:a.json")
	if err != nil {
		t.Fatalf("download() error = %v", err)
	}
	if string(content) != "file-content" {
		t.Fatalf("download() = %q, want file-content", content)
	}

	client = newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "404 Not Found", StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := client.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want status error")
	}

	client = newTestClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := client.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want transport error")
	}
}

func TestParseRepository(t *testing.T) {
	for _, resource := range []string{
		"bogus",
		"projects/p/locations/l",
		"wrong/p/locations/l/repositories/r",
		"projects/p/wrong/l/repositories/r",
		"projects/p/locations/l/wrong/r",
		"projects//locations/l/repositories/r",
		"projects/p/locations//repositories/r",
		"projects/p/locations/l/repositories/",
	} {
		if _, _, _, err := parseRepository(resource); err == nil {
			t.Errorf("parseRepository(%q) error = nil, want error", resource)
		}
	}
	project, location, repository, err := parseRepository("projects/p/locations/l/repositories/r")
	if err != nil {
		t.Fatalf("parseRepository() error = %v", err)
	}
	if project != "p" || location != "l" || repository != "r" {
		t.Fatalf("parseRepository() = %q, %q, %q", project, location, repository)
	}
}
