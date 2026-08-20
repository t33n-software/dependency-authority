package scanner

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

const testDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

const findingsDocument = `{
  "results": [
    {
      "source": {"path": "go.mod", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "example.com/mod", "version": "1.0.0", "ecosystem": "Go"},
          "vulnerabilities": [
            {"id": "GO-2026-0001", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
          ]
        }
      ]
    }
  ]
}`

func testCandidate(t *testing.T, name string) candidate.Candidate {
	t.Helper()
	subject, err := candidate.New(candidate.EcosystemGo, name, "v1.0.0", testDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return subject
}

func newScanner(t *testing.T, run Runner) OSV {
	t.Helper()
	adapter, err := NewOSV("osv-scanner", "db", "content", run)
	if err != nil {
		t.Fatalf("NewOSV() error = %v", err)
	}
	return adapter
}

func TestNewOSVValidatesConfiguration(t *testing.T) {
	runner := func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{}, nil
	}
	if _, err := NewOSV(" ", "db", "content", runner); err == nil {
		t.Fatal("NewOSV( blank tool ) error = nil, want error")
	}
	if _, err := NewOSV("osv-scanner", "", "content", runner); err == nil {
		t.Fatal("NewOSV( empty database ) error = nil, want error")
	}
	if _, err := NewOSV("osv-scanner", "db", " ", runner); err == nil {
		t.Fatal("NewOSV( blank content root ) error = nil, want error")
	}
	if _, err := NewOSV("osv-scanner", "db", "content", nil); err == nil {
		t.Fatal("NewOSV( nil runner ) error = nil, want error")
	}
	if _, err := NewOSV("osv-scanner", "db", "content", runner); err != nil {
		t.Fatalf("NewOSV() error = %v, want success", err)
	}
}

func TestScanRejectsEscapingContentPath(t *testing.T) {
	called := false
	adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		called = true
		return Result{}, nil
	})
	if _, err := adapter.Scan(context.Background(), testCandidate(t, "../../escape")); err == nil {
		t.Fatal("Scan() error = nil, want path escape error")
	}
	if called {
		t.Fatal("Scan() executed the tool for an escaping path, want rejection before execution")
	}
}

func TestScanPropagatesRunnerError(t *testing.T) {
	adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{}, errors.New("tool failed to start")
	})
	if _, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod")); err == nil {
		t.Fatal("Scan() error = nil, want runner error")
	}
}

func TestScanRejectsUnexpectedExitCodes(t *testing.T) {
	for _, code := range []int{2, 127, 128} {
		adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: code}, nil
		})
		if _, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod")); err == nil {
			t.Errorf("Scan( exit %d ) error = nil, want error", code)
		}
	}
}

func TestScanRejectsMalformedOutput(t *testing.T) {
	adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{Stdout: []byte("{"), ExitCode: 1}, nil
	})
	if _, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod")); err == nil {
		t.Fatal("Scan() error = nil, want decode error")
	}
}

func TestScanWithoutFindingsScoresZero(t *testing.T) {
	adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{Stdout: []byte(`{"results": []}`), ExitCode: 0}, nil
	})
	result, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.MaxCVSS != 0 {
		t.Fatalf("MaxCVSS = %v, want 0", result.MaxCVSS)
	}
}

func TestScanComputesMaxSeverity(t *testing.T) {
	adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{Stdout: []byte(findingsDocument), ExitCode: 1}, nil
	})
	result, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.MaxCVSS != 9.8 {
		t.Fatalf("MaxCVSS = %v, want 9.8", result.MaxCVSS)
	}
}

func TestScanAppliesTheConservativeScore(t *testing.T) {
	for name, document := range map[string]string{
		"cvss v4 only":   `{"results": [{"packages": [{"vulnerabilities": [{"id": "V4", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}]}]}]}`,
		"missing vector": `{"results": [{"packages": [{"vulnerabilities": [{"id": "NONE"}]}]}]}`,
		"broken vector":  `{"results": [{"packages": [{"vulnerabilities": [{"id": "BROKEN", "severity": [{"type": "CVSS_V3", "score": "bogus"}]}]}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			adapter := newScanner(t, func(context.Context, string, []string, string, ...string) (Result, error) {
				return Result{Stdout: []byte(document), ExitCode: 1}, nil
			})
			result, err := adapter.Scan(context.Background(), testCandidate(t, "example.com/mod"))
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if result.MaxCVSS != 10.0 {
				t.Fatalf("MaxCVSS = %v, want the conservative 10.0", result.MaxCVSS)
			}
		})
	}
}

func TestScanBindsToolContractAndContext(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "present")
	var gotDir, gotTool string
	var gotEnv, gotArgs []string
	adapter := newScanner(t, func(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error) {
		if ctx.Value(marker{}) != "present" {
			return Result{}, errors.New("context not propagated")
		}
		gotDir, gotEnv, gotTool, gotArgs = dir, env, name, args
		return Result{Stdout: []byte(`{"results": []}`), ExitCode: 0}, nil
	})
	if _, err := adapter.Scan(ctx, testCandidate(t, "example.com/mod")); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	wantDir := filepath.Join("content", "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
	if gotDir != wantDir {
		t.Fatalf("dir = %q, want %q", gotDir, wantDir)
	}
	if gotTool != "osv-scanner" {
		t.Fatalf("tool = %q, want osv-scanner", gotTool)
	}
	if !reflect.DeepEqual(gotArgs, []string{"scan", "--offline", "--format", "json", "."}) {
		t.Fatalf("args = %v, want the pinned offline JSON scan contract", gotArgs)
	}
	if !reflect.DeepEqual(gotEnv, []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=db"}) {
		t.Fatalf("env = %v, want the snapshot database binding", gotEnv)
	}
}

func TestExecRunner(t *testing.T) {
	result, err := ExecRunner(context.Background(), ".", nil, "go", "version")
	if err != nil {
		t.Fatalf("ExecRunner(go version) error = %v", err)
	}
	if result.ExitCode != 0 || !strings.Contains(string(result.Stdout), "go version") {
		t.Fatalf("ExecRunner(go version) = %+v, want exit 0 with version output", result)
	}

	failing, err := ExecRunner(context.Background(), ".", nil, "go", "nosuchcommand")
	if err != nil {
		t.Fatalf("ExecRunner(go nosuchcommand) error = %v, want a result with a non-zero exit code", err)
	}
	if failing.ExitCode == 0 {
		t.Fatal("ExecRunner(go nosuchcommand) exit code = 0, want non-zero")
	}

	if _, err := ExecRunner(context.Background(), ".", nil, "definitely-not-a-real-tool-xyz"); err == nil {
		t.Fatal("ExecRunner( unknown tool ) error = nil, want start error")
	}
}
