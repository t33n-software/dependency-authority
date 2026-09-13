package consumercontract

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testEndpoint = "https://europe-west3-go.pkg.dev/example-approved/go-dependencies-approved"

func okRunner(context.Context, string, []string, string, ...string) (Result, error) {
	return Result{}, nil
}

func newGo(t *testing.T, run Runner) Go {
	t.Helper()
	adapter, err := NewGo("go", t.TempDir(), testEndpoint, "/controller", run)
	if err != nil {
		t.Fatalf("NewGo() error = %v", err)
	}
	return adapter
}

func TestNewGoValidatesConfiguration(t *testing.T) {
	if _, err := NewGo(" ", "root", testEndpoint, "/controller", okRunner); err == nil {
		t.Fatal("NewGo( blank tool ) error = nil, want error")
	}
	if _, err := NewGo("go", " ", testEndpoint, "/controller", okRunner); err == nil {
		t.Fatal("NewGo( blank work root ) error = nil, want error")
	}
	for name, endpoint := range map[string]string{
		"empty":        "",
		"unparseable":  "%",
		"hostless":     "https:///no-host",
		"plain http":   "http://example.com/p/r",
		"non-loopback": "http://203.0.113.10/p/r",
		"ftp scheme":   "ftp://localhost/p/r",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGo("go", "root", endpoint, "/controller", okRunner); err == nil {
				t.Fatal("NewGo() error = nil, want the endpoint contract error")
			}
		})
	}
	for name, endpoint := range map[string]string{
		"loopback host": "http://localhost:54443/p/r",
		"loopback ip":   "http://127.0.0.1:54443/p/r",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGo("go", "root", endpoint, "/controller", okRunner); err != nil {
				t.Fatalf("NewGo( loopback test server ) error = %v, want success", err)
			}
		})
	}
	if _, err := NewGo("go", "root", testEndpoint, " ", okRunner); err == nil {
		t.Fatal("NewGo( blank executable ) error = nil, want error")
	}
	if _, err := NewGo("go", "root", testEndpoint, "/controller", nil); err == nil {
		t.Fatal("NewGo( nil runner ) error = nil, want error")
	}
	if _, err := NewGo("go", "root", testEndpoint+"/", "/controller", okRunner); err != nil {
		t.Fatalf("NewGo() error = %v, want success", err)
	}
}

func TestPrepareMaterializesTheConsumerWorkspace(t *testing.T) {
	root := t.TempDir()
	adapter, err := NewGo("go", root, testEndpoint, "/controller", okRunner)
	if err != nil {
		t.Fatalf("NewGo() error = %v", err)
	}
	dir, err := adapter.Prepare("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if dir != filepath.Join(root, "workspace") {
		t.Fatalf("Prepare() dir = %q, want the canonical workspace", dir)
	}
	goMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("ReadFile(go.mod) error = %v", err)
	}
	wantGoMod := "module consumer.verification/verify\n\ngo 1.26\n\nrequire example.com/mod v1.0.0\n"
	if string(goMod) != wantGoMod {
		t.Fatalf("go.mod = %q, want %q", goMod, wantGoMod)
	}
	mainGo, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatalf("ReadFile(main.go) error = %v", err)
	}
	wantMainGo := "package main\n\nimport _ \"example.com/mod\"\n\nfunc main() {}\n"
	if string(mainGo) != wantMainGo {
		t.Fatalf("main.go = %q, want %q", mainGo, wantMainGo)
	}
	for _, surface := range []string{"modcache", "buildcache", "gopath", "tmp", "home"} {
		info, err := os.Stat(filepath.Join(root, surface))
		if err != nil || !info.IsDir() {
			t.Fatalf("the %s surface is not materialized: %v", surface, err)
		}
	}
}

func TestPrepareRejectsEmptyInputs(t *testing.T) {
	adapter := newGo(t, okRunner)
	if _, err := adapter.Prepare(" ", "v1.0.0"); err == nil {
		t.Fatal("Prepare( blank module ) error = nil, want error")
	}
	if _, err := adapter.Prepare("example.com/mod", " "); err == nil {
		t.Fatal("Prepare( blank version ) error = nil, want error")
	}
}

func TestPrepareFailsClosedOnTheFilesystem(t *testing.T) {
	t.Run("surface creation", func(t *testing.T) {
		original := mkdirAll
		t.Cleanup(func() { mkdirAll = original })
		mkdirAll = func(string, os.FileMode) error { return errors.New("read-only root") }
		adapter := newGo(t, okRunner)
		if _, err := adapter.Prepare("example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Prepare() error = nil, want the surface creation failure")
		}
	})
	t.Run("workspace clearing", func(t *testing.T) {
		original := removeAll
		t.Cleanup(func() { removeAll = original })
		removeAll = func(string) error { return errors.New("locked tree") }
		adapter := newGo(t, okRunner)
		if _, err := adapter.Prepare("example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Prepare() error = nil, want the clearing failure")
		}
	})
	t.Run("workspace creation", func(t *testing.T) {
		original := mkdirAll
		t.Cleanup(func() { mkdirAll = original })
		calls := 0
		mkdirAll = func(path string, mode os.FileMode) error {
			calls++
			if path == filepath.Join("root", "workspace") {
				return errors.New("no space")
			}
			return os.MkdirAll(path, mode)
		}
		adapter, err := NewGo("go", "root", testEndpoint, "/controller", okRunner)
		if err != nil {
			t.Fatalf("NewGo() error = %v", err)
		}
		if _, err := adapter.Prepare("example.com/mod", "v1.0.0"); err == nil || calls == 0 {
			t.Fatalf("Prepare() error = %v, calls = %d, want the workspace creation failure", err, calls)
		}
	})
	t.Run("module contract write", func(t *testing.T) {
		original := writeFile
		t.Cleanup(func() { writeFile = original })
		writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
		adapter := newGo(t, okRunner)
		if _, err := adapter.Prepare("example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Prepare() error = nil, want the contract write failure")
		}
	})
	t.Run("module source write", func(t *testing.T) {
		original := writeFile
		t.Cleanup(func() { writeFile = original })
		writeFile = func(path string, content []byte, mode os.FileMode) error {
			if strings.HasSuffix(path, "main.go") {
				return errors.New("disk full")
			}
			return os.WriteFile(path, content, mode)
		}
		adapter := newGo(t, okRunner)
		if _, err := adapter.Prepare("example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Prepare() error = nil, want the source write failure")
		}
	})
}

func TestRelease(t *testing.T) {
	root := t.TempDir()
	adapter, err := NewGo("go", root, testEndpoint, "/controller", okRunner)
	if err != nil {
		t.Fatalf("NewGo() error = %v", err)
	}
	dir, err := adapter.Prepare("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := adapter.Release(dir); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the workspace survives Release(), want removal")
	}

	original := removeAll
	t.Cleanup(func() { removeAll = original })
	removeAll = func(string) error { return errors.New("locked tree") }
	if err := adapter.Release(dir); err == nil {
		t.Fatal("Release() error = nil, want the removal failure")
	}
}

func TestDownloadBindsTheControlledEnvironment(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "present")
	var gotDir, gotTool string
	var gotEnv, gotArgs []string
	root := t.TempDir()
	adapter, err := NewGo("go", root, testEndpoint, "/controller", func(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error) {
		if ctx.Value(marker{}) != "present" {
			return Result{}, errors.New("context not propagated")
		}
		gotDir, gotEnv, gotTool, gotArgs = dir, env, name, args
		return Result{Stdout: []byte(`{"Sum":"h1:abc="}`)}, nil
	})
	if err != nil {
		t.Fatalf("NewGo() error = %v", err)
	}
	sum, err := adapter.Download(ctx, "workspace", "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if sum != "h1:abc=" {
		t.Fatalf("Download() sum = %q, want the endpoint-attested sum", sum)
	}
	if gotDir != "workspace" || gotTool != "go" {
		t.Fatalf("dir = %q, tool = %q, want the workspace and the pinned tool", gotDir, gotTool)
	}
	if len(gotArgs) != 4 || gotArgs[0] != "mod" || gotArgs[1] != "download" || gotArgs[2] != "-json" || gotArgs[3] != "example.com/mod@v1.0.0" {
		t.Fatalf("args = %v, want the positive resolution contract", gotArgs)
	}
	want := map[string]string{
		"GO111MODULE": "on",
		"GOPROXY":     testEndpoint,
		"GOAUTH":      "/controller goauth",
		"GONOSUMDB":   "*",
		"GONOPROXY":   "",
		"GOPRIVATE":   "",
		"GOFLAGS":     "-mod=mod",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOENV":       "off",
		"CGO_ENABLED": "0",
		"GOMODCACHE":  filepath.Join(root, "modcache"),
		"GOCACHE":     filepath.Join(root, "buildcache"),
		"GOPATH":      filepath.Join(root, "gopath"),
		"GOTMPDIR":    filepath.Join(root, "tmp"),
		"HOME":        filepath.Join(root, "home"),
	}
	bound := map[string]string{}
	for _, entry := range gotEnv {
		key, value, _ := strings.Cut(entry, "=")
		bound[key] = value
	}
	if len(gotEnv) != len(want) {
		t.Fatalf("environment = %d entries, want %d", len(gotEnv), len(want))
	}
	for key, value := range want {
		if bound[key] != value {
			t.Errorf("environment %s = %q, want %q", key, bound[key], value)
		}
	}
}

func TestDownloadFailsClosed(t *testing.T) {
	t.Run("execution failure", func(t *testing.T) {
		adapter := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{}, errors.New("tool failed to start")
		})
		if _, err := adapter.Download(context.Background(), "dir", "example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Download() error = nil, want the execution failure")
		}
	})
	t.Run("non-zero exit", func(t *testing.T) {
		adapter := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: 1, Stderr: []byte("no matching versions")}, nil
		})
		if _, err := adapter.Download(context.Background(), "dir", "example.com/mod", "v1.0.0"); err == nil ||
			!strings.Contains(err.Error(), "no matching versions") {
			t.Fatalf("Download() error = %v, want the exit failure with the toolchain diagnostics", err)
		}
	})
	t.Run("malformed result", func(t *testing.T) {
		adapter := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{Stdout: []byte("{")}, nil
		})
		if _, err := adapter.Download(context.Background(), "dir", "example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Download() error = nil, want the decode failure")
		}
	})
	t.Run("missing module sum", func(t *testing.T) {
		adapter := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{Stdout: []byte(`{"Sum":""}`)}, nil
		})
		if _, err := adapter.Download(context.Background(), "dir", "example.com/mod", "v1.0.0"); err == nil {
			t.Fatal("Download() error = nil, want the missing-sum failure")
		}
	})
}

func TestProbeFailsClosed(t *testing.T) {
	adapter := newGo(t, func(_ context.Context, _ string, _ []string, _ string, args ...string) (Result, error) {
		if len(args) != 3 || args[2] != "example.invalid/never-admitted@v0.0.0" {
			return Result{}, errors.New("unexpected probe reference")
		}
		return Result{ExitCode: 1}, nil
	})
	if err := adapter.ProbeFailsClosed(context.Background(), "dir", "example.invalid/never-admitted@v0.0.0"); err != nil {
		t.Fatalf("ProbeFailsClosed() error = %v, want the proven fail-closed probe", err)
	}

	if err := adapter.ProbeFailsClosed(context.Background(), "dir", " "); err == nil {
		t.Fatal("ProbeFailsClosed( blank reference ) error = nil, want error")
	}

	t.Run("execution failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{}, errors.New("tool failed to start")
		})
		if err := failing.ProbeFailsClosed(context.Background(), "dir", "example.invalid/never-admitted@v0.0.0"); err == nil {
			t.Fatal("ProbeFailsClosed() error = nil, want the execution failure")
		}
	})
	t.Run("a resolution is a supply-chain anomaly", func(t *testing.T) {
		anomaly := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: 0}, nil
		})
		err := anomaly.ProbeFailsClosed(context.Background(), "dir", "example.invalid/never-admitted@v0.0.0")
		if err == nil || !strings.Contains(err.Error(), "supply-chain anomaly") {
			t.Fatalf("ProbeFailsClosed() error = %v, want the anomaly failure", err)
		}
	})
}

func TestGraphStable(t *testing.T) {
	calls := 0
	adapter := newGo(t, func(_ context.Context, _ string, _ []string, _ string, args ...string) (Result, error) {
		calls++
		return Result{}, nil
	})
	if err := adapter.GraphStable(context.Background(), "dir"); err != nil {
		t.Fatalf("GraphStable() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("GraphStable() ran %d toolchain executions, want the establish-then-prove pair", calls)
	}

	t.Run("establish failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{}, errors.New("tool failed to start")
		})
		if err := failing.GraphStable(context.Background(), "dir"); err == nil {
			t.Fatal("GraphStable() error = nil, want the establish failure")
		}
	})
	t.Run("establish exit failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: 1, Stderr: []byte("unresolved import")}, nil
		})
		err := failing.GraphStable(context.Background(), "dir")
		if err == nil || !strings.Contains(err.Error(), "unresolved import") {
			t.Fatalf("GraphStable() error = %v, want the establish exit failure with diagnostics", err)
		}
	})
	t.Run("proof execution failure", func(t *testing.T) {
		calls := 0
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			calls++
			if calls == 2 {
				return Result{}, errors.New("tool failed to start")
			}
			return Result{}, nil
		})
		if err := failing.GraphStable(context.Background(), "dir"); err == nil {
			t.Fatal("GraphStable() error = nil, want the proof execution failure")
		}
	})
	t.Run("a non-empty diff is a graph mutation", func(t *testing.T) {
		calls := 0
		mutating := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			calls++
			if calls == 2 {
				return Result{ExitCode: 1}, nil
			}
			return Result{}, nil
		})
		err := mutating.GraphStable(context.Background(), "dir")
		if err == nil || !strings.Contains(err.Error(), "graph mutation") {
			t.Fatalf("GraphStable() error = %v, want the graph mutation failure", err)
		}
	})
}

func TestVerifyIntegrity(t *testing.T) {
	adapter := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
		return Result{Stdout: []byte("all modules verified\n")}, nil
	})
	if err := adapter.VerifyIntegrity(context.Background(), "dir"); err != nil {
		t.Fatalf("VerifyIntegrity() error = %v", err)
	}

	t.Run("execution failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{}, errors.New("tool failed to start")
		})
		if err := failing.VerifyIntegrity(context.Background(), "dir"); err == nil {
			t.Fatal("VerifyIntegrity() error = nil, want the execution failure")
		}
	})
	t.Run("exit failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: 1, Stderr: []byte("checksum mismatch")}, nil
		})
		err := failing.VerifyIntegrity(context.Background(), "dir")
		if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("VerifyIntegrity() error = %v, want the exit failure with diagnostics", err)
		}
	})
	t.Run("missing verification marker", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{Stdout: []byte("nothing\n")}, nil
		})
		if err := failing.VerifyIntegrity(context.Background(), "dir"); err == nil {
			t.Fatal("VerifyIntegrity() error = nil, want the missing-marker failure")
		}
	})
}

func TestBuildEvidence(t *testing.T) {
	const moduleTable = "consumer.bin: go1.26.6\n" +
		"\tpath\tconsumer.verification/verify\n" +
		"\tmod\tconsumer.verification/verify\t(devel)\t\n" +
		"\tdep\texample.com/other\tv2.0.0\th1:other=\n" +
		"\tdep\texample.com/mod\tv1.0.0\th1:abc=\n"
	adapter := newGo(t, func(_ context.Context, _ string, _ []string, _ string, args ...string) (Result, error) {
		if len(args) > 0 && args[0] == "version" {
			return Result{Stdout: []byte(moduleTable)}, nil
		}
		return Result{}, nil
	})
	version, sum, err := adapter.BuildEvidence(context.Background(), "dir", "example.com/mod")
	if err != nil {
		t.Fatalf("BuildEvidence() error = %v", err)
	}
	if version != "v1.0.0" || sum != "h1:abc=" {
		t.Fatalf("BuildEvidence() = %q %q, want the artifact-carried identity", version, sum)
	}

	t.Run("build execution failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{}, errors.New("tool failed to start")
		})
		if _, _, err := failing.BuildEvidence(context.Background(), "dir", "example.com/mod"); err == nil {
			t.Fatal("BuildEvidence() error = nil, want the build execution failure")
		}
	})
	t.Run("build exit failure", func(t *testing.T) {
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			return Result{ExitCode: 1, Stderr: []byte("does not compile")}, nil
		})
		err := fail3(failing.BuildEvidence(context.Background(), "dir", "example.com/mod"))
		if err == nil || !strings.Contains(err.Error(), "does not compile") {
			t.Fatalf("BuildEvidence() error = %v, want the build exit failure with diagnostics", err)
		}
	})
	t.Run("module table execution failure", func(t *testing.T) {
		calls := 0
		failing := newGo(t, func(context.Context, string, []string, string, ...string) (Result, error) {
			calls++
			if calls == 2 {
				return Result{}, errors.New("tool failed to start")
			}
			return Result{}, nil
		})
		if _, _, err := failing.BuildEvidence(context.Background(), "dir", "example.com/mod"); err == nil {
			t.Fatal("BuildEvidence() error = nil, want the module table execution failure")
		}
	})
	t.Run("module table exit failure", func(t *testing.T) {
		failing := newGo(t, func(_ context.Context, _ string, _ []string, _ string, args ...string) (Result, error) {
			if len(args) > 0 && args[0] == "version" {
				return Result{ExitCode: 1, Stderr: []byte("not a binary")}, nil
			}
			return Result{}, nil
		})
		err := fail3(failing.BuildEvidence(context.Background(), "dir", "example.com/mod"))
		if err == nil || !strings.Contains(err.Error(), "not a binary") {
			t.Fatalf("BuildEvidence() error = %v, want the module table exit failure with diagnostics", err)
		}
	})
	t.Run("the artifact must carry the module", func(t *testing.T) {
		missing := newGo(t, func(_ context.Context, _ string, _ []string, _ string, args ...string) (Result, error) {
			if len(args) > 0 && args[0] == "version" {
				return Result{Stdout: []byte(moduleTable)}, nil
			}
			return Result{}, nil
		})
		err := fail3(missing.BuildEvidence(context.Background(), "dir", "example.com/absent"))
		if err == nil || !strings.Contains(err.Error(), "no module table entry") {
			t.Fatalf("BuildEvidence() error = %v, want the missing module entry failure", err)
		}
	})
}

// fail3 collapses the triple return of BuildEvidence for error assertions.
func fail3(_ string, _ string, err error) error {
	return err
}

func TestCredentialSet(t *testing.T) {
	content, err := CredentialSet(testEndpoint, "token-123")
	if err != nil {
		t.Fatalf("CredentialSet() error = %v", err)
	}
	want := testEndpoint + "/\n\nAuthorization: Bearer token-123\n\n"
	if string(content) != want {
		t.Fatalf("CredentialSet() = %q, want %q", content, want)
	}

	if _, err := CredentialSet("http://example.com/p/r", "token-123"); err == nil {
		t.Fatal("CredentialSet( plain http ) error = nil, want the endpoint contract error")
	}
	if _, err := CredentialSet(testEndpoint, " "); err == nil {
		t.Fatal("CredentialSet( blank token ) error = nil, want error")
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
	if !strings.Contains(string(failing.Stderr), "unknown command") {
		t.Fatalf("ExecRunner(go nosuchcommand) stderr = %q, want the captured tool diagnostics", failing.Stderr)
	}

	if _, err := ExecRunner(context.Background(), ".", nil, "definitely-not-a-real-tool-xyz"); err == nil {
		t.Fatal("ExecRunner( unknown tool ) error = nil, want start error")
	}
}

func TestStderrExcerpt(t *testing.T) {
	overCap := strings.Repeat("x", stderrExcerptRunes+10)
	tests := map[string]struct {
		stderr string
		want   string
	}{
		"empty":              {"", ""},
		"whitespace only":    {" \n\t\n ", ""},
		"short diagnostic":   {"could not resolve", ": could not resolve"},
		"multiline collapse": {"first line\nsecond line\n", ": first line second line"},
		"over cap":           {overCap, ": " + strings.Repeat("x", stderrExcerptRunes) + "…"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := stderrExcerpt([]byte(test.stderr)); got != test.want {
				t.Fatalf("stderrExcerpt() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBoundedBuffer(t *testing.T) {
	buffer := &boundedBuffer{limit: 8}
	if n, err := buffer.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatalf("Write(short) = (%d, %v), want (4, nil)", n, err)
	}
	if n, err := buffer.Write([]byte("efghijkl")); err != nil || n != 8 {
		t.Fatalf("Write(over-cap) = (%d, %v), want (8, nil) — the child never blocks on the discarded tail", n, err)
	}
	if got := buffer.buf.String(); got != "abcdefgh" {
		t.Fatalf("retained = %q, want the bounded head %q", got, "abcdefgh")
	}
	if n, err := buffer.Write([]byte("more")); err != nil || n != 4 {
		t.Fatalf("Write(at-cap) = (%d, %v), want (4, nil)", n, err)
	}
	if got := buffer.buf.String(); got != "abcdefgh" {
		t.Fatalf("retained after the at-cap write = %q, want the unchanged bounded head", got)
	}
}
