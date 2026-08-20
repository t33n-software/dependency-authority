package artifactregistry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func newGate(t *testing.T, doer Doer) Gate {
	t.Helper()
	gate, err := NewGate(newTestClient(t, doer), "projects/p/locations/l/repositories/r")
	if err != nil {
		t.Fatalf("NewGate() error = %v", err)
	}
	return gate
}

func TestNewGateValidatesConfiguration(t *testing.T) {
	client := newTestClient(t, http.DefaultClient)
	if _, err := NewGate(client, "bogus"); err == nil {
		t.Fatal("NewGate( invalid repository ) error = nil, want error")
	}
	if _, err := NewGate(client, "projects/p/locations/l/repositories/r"); err != nil {
		t.Fatalf("NewGate() error = %v, want success", err)
	}
}

func TestGateBlockCreatesTheDenyRule(t *testing.T) {
	var gotURL, gotMethod string
	var body ruleBody
	gate := newGate(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotMethod = req.Method
		content, _ := io.ReadAll(req.Body)
		if err := json.Unmarshal(content, &body); err != nil {
			t.Fatalf("decode rule body: %v", err)
		}
		return okResponse(`{"name": "projects/p/locations/l/repositories/r/rules/x", "action": "DENY", "operation": "DOWNLOAD"}`), nil
	}))

	subject := newCandidate(t)
	if err := gate.Block(context.Background(), subject); err != nil {
		t.Fatalf("Block() error = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if !strings.Contains(gotURL, "/projects/p/locations/l/repositories/r/rules?ruleId=revoke-") {
		t.Fatalf("URL = %q, want the rules create surface with the derived rule id", gotURL)
	}
	if body.Action != "DENY" || body.PackageID != "example.com/mod" {
		t.Fatalf("rule body = %+v, want DENY on the module", body)
	}
	if body.Condition.Expression != "pkg.version.id == 'v1.0.0'" {
		t.Fatalf("condition = %q, want the version-scoped expression", body.Condition.Expression)
	}
}

func TestGateBlockIsIdempotentOnConflict(t *testing.T) {
	gate := newGate(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "409 Conflict", StatusCode: http.StatusConflict, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err := gate.Block(context.Background(), newCandidate(t)); err != nil {
		t.Fatalf("Block() error = %v, want idempotent success", err)
	}
}

func TestGateBlockFailures(t *testing.T) {
	gate := newGate(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err := gate.Block(context.Background(), newCandidate(t)); err == nil {
		t.Fatal("Block() error = nil, want status error")
	}

	gate = newGate(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if err := gate.Block(context.Background(), newCandidate(t)); err == nil {
		t.Fatal("Block() error = nil, want transport error")
	}
}

func TestGateBlockRejectsQuotedIdentity(t *testing.T) {
	gate := newGate(t, http.DefaultClient)

	quotedName, err := candidateWithIdentity("example.com/'mod'", "v1.0.0")
	if err != nil {
		t.Fatalf("candidateWithIdentity() error = %v", err)
	}
	if err := gate.Block(context.Background(), quotedName); err == nil {
		t.Fatal("Block() error = nil, want quoted name error")
	}

	quotedVersion, err := candidateWithIdentity("example.com/mod", "v1.0'0")
	if err != nil {
		t.Fatalf("candidateWithIdentity() error = %v", err)
	}
	if err := gate.Block(context.Background(), quotedVersion); err == nil {
		t.Fatal("Block() error = nil, want quoted version error")
	}
}

func TestRuleIDIsDeterministicAndScoped(t *testing.T) {
	first := newCandidate(t)
	second, err := candidateWithIdentity("example.com/mod", "v2.0.0")
	if err != nil {
		t.Fatalf("candidateWithIdentity() error = %v", err)
	}
	firstCall := ruleID(first)
	secondCall := ruleID(first)
	if firstCall != secondCall {
		t.Fatal("ruleID() not deterministic")
	}
	if ruleID(first) == ruleID(second) {
		t.Fatal("ruleID() identical for different versions, want scoped ids")
	}
	if !strings.HasPrefix(ruleID(first), "revoke-") {
		t.Fatalf("ruleID() = %q, want the revoke- prefix", ruleID(first))
	}
}
