// Package artifactregistry implements the Artifact-Registry-backed outbound
// ports of the dependency authority lanes: the append-only candidate records
// store, the approved-zone publisher with the Go content-identity proof, and
// the revocation download gate. The package binds no organization value; the
// trust-zone endpoints and repositories arrive through the lane environment.
package artifactregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// Doer executes HTTP requests. *http.Client satisfies it; tests inject fakes.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TokenSource supplies a short-lived bearer token per request. The token
// never persists beyond the request it authorizes.
type TokenSource func(ctx context.Context) (string, error)

// Client is the authenticated Artifact Registry transport shared by the
// adapters of this package.
type Client struct {
	api   string
	doer  Doer
	token TokenSource
}

// NewClient constructs the transport and fails closed on an empty endpoint,
// a non-TLS transport outside loopback test servers, a nil token source, or
// a nil HTTP client.
func NewClient(apiEndpoint string, token TokenSource, doer Doer) (Client, error) {
	if strings.TrimSpace(apiEndpoint) == "" {
		return Client{}, errors.New("artifact registry API endpoint must not be empty")
	}
	parsed, err := url.Parse(apiEndpoint)
	if err != nil {
		return Client{}, fmt.Errorf("parse artifact registry API endpoint: %w", err)
	}
	if parsed.Host == "" {
		return Client{}, fmt.Errorf("artifact registry API endpoint %q must carry a host", apiEndpoint)
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return Client{}, fmt.Errorf("artifact registry API endpoint %q must use https", apiEndpoint)
	}
	if token == nil {
		return Client{}, errors.New("token source must not be nil")
	}
	if doer == nil {
		return Client{}, errors.New("http client must not be nil")
	}
	return Client{api: strings.TrimRight(apiEndpoint, "/"), doer: doer, token: token}, nil
}

// do issues one authenticated request and returns the response body and
// status code. Transport and read failures are errors; status handling
// belongs to the caller.
func (c Client) do(ctx context.Context, method string, requestURL string, body []byte, contentType string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build artifact registry request: %w", err)
	}
	token, err := c.token(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve artifact registry credential: %w", err)
	}
	if token == "" {
		return nil, 0, errors.New("artifact registry credential must not be empty")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", contentType)
	}

	response, err := c.doer.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("execute artifact registry request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read artifact registry response: %w", err)
	}
	return content, response.StatusCode, nil
}

// upload stores one immutable file in the bound generic repository through
// the genericArtifacts:create media upload. A conflict means the identical
// content-addressed file already exists and is an idempotent success.
func (c Client) upload(ctx context.Context, repository string, packageID string, versionID string, filename string, content []byte) error {
	body, contentType := encodeUpload(packageID, versionID, filename, content)
	requestURL := c.api + "/upload/v1/" + repository + "/genericArtifacts:create"
	_, status, err := c.do(ctx, http.MethodPost, requestURL, body, contentType)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return nil
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("upload %q to %q: unexpected status %d", filename, repository, status)
	}
	return nil
}

// fileEntry is the listed shape of one stored generic file.
type fileEntry struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	CreateTime string `json:"createTime"`
}

// list returns every file in the repository owned by the bound package
// version, following the list pagination contract.
func (c Client) list(ctx context.Context, repository string, packageID string, versionID string) ([]fileEntry, error) {
	owner := repository + "/packages/" + packageID + "/versions/" + versionID
	matches := make([]fileEntry, 0)
	pageToken := ""
	for {
		requestURL := c.api + "/v1/" + repository + "/files?pageSize=1000"
		if pageToken != "" {
			requestURL += "&pageToken=" + url.QueryEscape(pageToken)
		}
		content, status, err := c.do(ctx, http.MethodGet, requestURL, nil, "")
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("list files of %q: unexpected status %d", repository, status)
		}
		page, err := decodeFilePage(content)
		if err != nil {
			return nil, fmt.Errorf("decode file list of %q: %w", repository, err)
		}
		for _, file := range page.Files {
			if file.Owner == owner {
				matches = append(matches, file)
			}
		}
		if page.NextPageToken == "" {
			return matches, nil
		}
		pageToken = page.NextPageToken
	}
}

// download fetches one stored file by its server-issued resource name.
func (c Client) download(ctx context.Context, name string) ([]byte, error) {
	content, status, err := c.do(ctx, http.MethodGet, c.api+"/v1/"+name+":download", nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("download %q: unexpected status %d", name, status)
	}
	return content, nil
}

// filePage is one page of the files.list response.
type filePage struct {
	Files         []fileEntry `json:"files"`
	NextPageToken string      `json:"nextPageToken"`
}

func decodeFilePage(content []byte) (filePage, error) {
	var page filePage
	if err := json.Unmarshal(content, &page); err != nil {
		return filePage{}, err
	}
	return page, nil
}

// encodeUpload builds the multipart media upload body: the JSON metadata part
// followed by the raw content part. The parts are adapter-controlled (static
// headers and digest-derived file names), so construction cannot fail.
func encodeUpload(packageID string, versionID string, filename string, content []byte) ([]byte, string) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	meta, _ := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {"application/json"},
		"Content-Disposition": {`form-data; name="meta"`},
	})
	_, _ = meta.Write([]byte(`{"filename":"` + filename + `","package_id":"` + packageID + `","version_id":"` + versionID + `"}`))

	blob, _ := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {"application/octet-stream"},
		"Content-Disposition": {`form-data; name="blob"; filename="` + filename + `"`},
	})
	_, _ = blob.Write(content)
	_ = writer.Close()
	return buffer.Bytes(), writer.FormDataContentType()
}

// parseRepository binds and validates the repository resource name
// projects/<project>/locations/<location>/repositories/<repository>.
func parseRepository(resource string) (project string, location string, repository string, err error) {
	parts := strings.Split(resource, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "repositories" {
		return "", "", "", fmt.Errorf("repository resource %q must match projects/<project>/locations/<location>/repositories/<repository>", resource)
	}
	if parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return "", "", "", fmt.Errorf("repository resource %q must not carry empty segments", resource)
	}
	return parts[1], parts[3], parts[5], nil
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
