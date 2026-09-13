// Package consumercontract implements the consumerverification.Contract port:
// the ecosystem's real pinned toolchain executes the consumer contract against
// the live approved endpoint. The adapter never reimplements the consumer
// contract — only the real toolchain defines the consumer-visible semantics —
// and the toolchain authenticates through the workload's own identity with the
// GOAUTH command form, never through credential files, injected environment
// credentials, or mounted secrets.
package consumercontract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// stderrCaptureBytes bounds the toolchain diagnostics retained from the
	// child process, so a verbose or looping tool can never exhaust memory.
	stderrCaptureBytes = 4096
	// stderrExcerptRunes bounds the single-line diagnostics excerpt the
	// fail-closed error chain carries.
	stderrExcerptRunes = 200
)

// TokenSource supplies a short-lived bearer token per call. The token never
// persists beyond the use it authorizes.
type TokenSource func(ctx context.Context) (string, error)

// Result carries the process outcome of one toolchain execution.
type Result struct {
	Stdout []byte
	// Stderr carries the toolchain diagnostics captured up to
	// stderrCaptureBytes; the fail-closed error path reduces them to a
	// bounded excerpt.
	Stderr   []byte
	ExitCode int
}

// Runner executes the pinned toolchain. ExecRunner satisfies it in production.
type Runner func(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error)

// Go is the consumer-contract adapter over the real pinned Go toolchain
// carried by the workload image.
type Go struct {
	tool             string
	workRoot         string
	approvedEndpoint string
	executable       string
	run              Runner
}

// NewGo constructs the adapter and fails closed on an empty tool, work-root,
// or executable binding, an invalid approved endpoint, or a nil runner.
func NewGo(tool string, workRoot string, approvedEndpoint string, executable string, run Runner) (Go, error) {
	if strings.TrimSpace(tool) == "" {
		return Go{}, errors.New("go tool path must not be empty")
	}
	if strings.TrimSpace(workRoot) == "" {
		return Go{}, errors.New("consumer work root must not be empty")
	}
	if err := validateEndpoint(approvedEndpoint); err != nil {
		return Go{}, err
	}
	if strings.TrimSpace(executable) == "" {
		return Go{}, errors.New("controller executable path must not be empty")
	}
	if run == nil {
		return Go{}, errors.New("toolchain runner must not be nil")
	}
	return Go{
		tool:             tool,
		workRoot:         workRoot,
		approvedEndpoint: strings.TrimRight(strings.TrimSpace(approvedEndpoint), "/"),
		executable:       executable,
		run:              run,
	}, nil
}

// validateEndpoint binds the approved endpoint contract: an HTTPS URL with a
// host, or a loopback test server.
func validateEndpoint(approvedEndpoint string) error {
	if strings.TrimSpace(approvedEndpoint) == "" {
		return errors.New("approved endpoint must not be empty")
	}
	parsed, err := url.Parse(approvedEndpoint)
	if err != nil {
		return fmt.Errorf("parse approved endpoint: %w", err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("approved endpoint %q must carry a host", approvedEndpoint)
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return fmt.Errorf("approved endpoint %q must use https", approvedEndpoint)
	}
	return nil
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

// The filesystem seams of the workspace lifecycle; the tests bind
// fault-injecting fakes.
var (
	removeAll = os.RemoveAll
	mkdirAll  = os.MkdirAll
	writeFile = os.WriteFile
)

// workspaceDir returns the canonical consumer workspace within the bound work
// root.
func (g Go) workspaceDir() string {
	return filepath.Join(g.workRoot, "workspace")
}

// Prepare materializes the consumer module workspace: a minimal consumer
// module that requires and imports the admitted module, with every writable
// toolchain surface inside the bound work root. Preparation is idempotent: a
// previous workspace is cleared first.
func (g Go) Prepare(module string, version string) (string, error) {
	if strings.TrimSpace(module) == "" {
		return "", errors.New("module must not be empty")
	}
	if strings.TrimSpace(version) == "" {
		return "", errors.New("version must not be empty")
	}
	for _, surface := range []string{"modcache", "buildcache", "gopath", "tmp", "home"} {
		if err := mkdirAll(filepath.Join(g.workRoot, surface), 0o755); err != nil {
			return "", fmt.Errorf("create the %s surface of the work root: %w", surface, err)
		}
	}
	dir := g.workspaceDir()
	if err := removeAll(dir); err != nil {
		return "", fmt.Errorf("clear the consumer workspace: %w", err)
	}
	if err := mkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create the consumer workspace: %w", err)
	}
	goMod := "module consumer.verification/verify\n\ngo 1.26\n\nrequire " + module + " " + version + "\n"
	if err := writeFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return "", fmt.Errorf("write the consumer module contract: %w", err)
	}
	mainGo := "package main\n\nimport _ \"" + module + "\"\n\nfunc main() {}\n"
	if err := writeFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		return "", fmt.Errorf("write the consumer module source: %w", err)
	}
	return dir, nil
}

// Release removes the consumer workspace. The workspace is ephemeral per
// execution; the lane releases it after the proofs ran.
func (g Go) Release(dir string) error {
	if err := removeAll(dir); err != nil {
		return fmt.Errorf("release the consumer workspace: %w", err)
	}
	return nil
}

// environment binds the controlled toolchain environment: the approved
// endpoint as the only module proxy, the workload's own GOAUTH command, no
// public checksum database and no VCS or proxy fallback, the pinned local
// toolchain, and every writable surface inside the bound work root.
func (g Go) environment() []string {
	return []string{
		"GO111MODULE=on",
		"GOPROXY=" + g.approvedEndpoint,
		"GOAUTH=" + g.executable + " goauth",
		"GONOSUMDB=*",
		"GONOPROXY=",
		"GOPRIVATE=",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"GOVCS=*:off",
		"GOENV=off",
		"CGO_ENABLED=0",
		"GOMODCACHE=" + filepath.Join(g.workRoot, "modcache"),
		"GOCACHE=" + filepath.Join(g.workRoot, "buildcache"),
		"GOPATH=" + filepath.Join(g.workRoot, "gopath"),
		"GOTMPDIR=" + filepath.Join(g.workRoot, "tmp"),
		"HOME=" + filepath.Join(g.workRoot, "home"),
	}
}

// Download runs the positive resolution: the admitted module version resolves
// through the approved endpoint. It returns the endpoint-attested module sum.
func (g Go) Download(ctx context.Context, dir string, module string, version string) (string, error) {
	result, err := g.run(ctx, dir, g.environment(), g.tool, "mod", "download", "-json", module+"@"+version)
	if err != nil {
		return "", fmt.Errorf("execute go mod download: %w", err)
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("go mod download %s@%s exited with code %d%s", module, version, result.ExitCode, stderrExcerpt(result.Stderr))
	}
	var document struct {
		Sum string `json:"Sum"`
	}
	if err := json.Unmarshal(result.Stdout, &document); err != nil {
		return "", fmt.Errorf("decode the go mod download result: %w", err)
	}
	if !strings.HasPrefix(document.Sum, "h1:") {
		return "", fmt.Errorf("go mod download %s@%s carried no h1 module sum", module, version)
	}
	return document.Sum, nil
}

// ProbeFailsClosed runs the negative resolution: the never-admitted reference
// must fail closed at the approved endpoint; a resolution of one is a
// supply-chain anomaly.
func (g Go) ProbeFailsClosed(ctx context.Context, dir string, reference string) error {
	if strings.TrimSpace(reference) == "" {
		return errors.New("negative probe reference must not be empty")
	}
	result, err := g.run(ctx, dir, g.environment(), g.tool, "mod", "download", reference)
	if err != nil {
		return fmt.Errorf("execute the negative probe: %w", err)
	}
	if result.ExitCode == 0 {
		return fmt.Errorf("the never-admitted reference %q resolved through the approved endpoint: supply-chain anomaly", reference)
	}
	return nil
}

// GraphStable runs the graph-mutation check: after the admitted graph is
// established, re-resolving it reports no change (go mod tidy -diff exits
// non-zero when the diff is not empty).
func (g Go) GraphStable(ctx context.Context, dir string) error {
	result, err := g.run(ctx, dir, g.environment(), g.tool, "mod", "tidy")
	if err != nil {
		return fmt.Errorf("execute go mod tidy: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("go mod tidy exited with code %d%s", result.ExitCode, stderrExcerpt(result.Stderr))
	}
	result, err = g.run(ctx, dir, g.environment(), g.tool, "mod", "tidy", "-diff")
	if err != nil {
		return fmt.Errorf("execute go mod tidy -diff: %w", err)
	}
	if result.ExitCode != 0 {
		return errors.New("go mod tidy -diff reports a graph mutation")
	}
	return nil
}

// VerifyIntegrity runs the ecosystem integrity proof over the resolved
// content.
func (g Go) VerifyIntegrity(ctx context.Context, dir string) error {
	result, err := g.run(ctx, dir, g.environment(), g.tool, "mod", "verify")
	if err != nil {
		return fmt.Errorf("execute go mod verify: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("go mod verify exited with code %d%s", result.ExitCode, stderrExcerpt(result.Stderr))
	}
	if !strings.Contains(string(result.Stdout), "all modules verified") {
		return errors.New("go mod verify did not confirm all modules verified")
	}
	return nil
}

// BuildEvidence runs the build-evidence correspondence: a consumer artifact
// is built from the admitted graph, and the artifact's module table must
// carry the admitted module. It returns the artifact-carried version and
// module sum.
func (g Go) BuildEvidence(ctx context.Context, dir string, module string) (string, string, error) {
	artifact := filepath.Join(dir, "consumer.bin")
	result, err := g.run(ctx, dir, g.environment(), g.tool, "build", "-o", artifact, ".")
	if err != nil {
		return "", "", fmt.Errorf("execute go build: %w", err)
	}
	if result.ExitCode != 0 {
		return "", "", fmt.Errorf("go build exited with code %d%s", result.ExitCode, stderrExcerpt(result.Stderr))
	}
	result, err = g.run(ctx, dir, g.environment(), g.tool, "version", "-m", artifact)
	if err != nil {
		return "", "", fmt.Errorf("execute go version -m: %w", err)
	}
	if result.ExitCode != 0 {
		return "", "", fmt.Errorf("go version -m exited with code %d%s", result.ExitCode, stderrExcerpt(result.Stderr))
	}
	return moduleEvidence(result.Stdout, module)
}

// moduleEvidence extracts the artifact-carried identity of the admitted
// module from the go version -m module table and fails closed when the table
// does not carry the module.
func moduleEvidence(output []byte, module string) (string, string, error) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) >= 4 && fields[0] == "dep" && fields[1] == module {
			return fields[2], fields[3], nil
		}
	}
	return "", "", fmt.Errorf("the consumer artifact carries no module table entry for %q", module)
}

// CredentialSet renders the GOAUTH command output for the approved endpoint:
// the endpoint URL line set followed by the bearer header of the workload's
// own short-lived token. The token never leaves the process and is never
// written to a file, the environment, or a mounted surface.
func CredentialSet(approvedEndpoint string, token string) ([]byte, error) {
	if err := validateEndpoint(approvedEndpoint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("workload token must not be empty")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(approvedEndpoint), "/")
	content := endpoint + "/\n\nAuthorization: Bearer " + token + "\n\n"
	return []byte(content), nil
}

// ExecRunner executes the pinned toolchain as a child process. A non-zero
// exit code is a result, not an error; only a failed start is an error. The
// toolchain diagnostics on standard error are captured up to
// stderrCaptureBytes.
func ExecRunner(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	stderr := &boundedBuffer{limit: stderrCaptureBytes}
	command.Stderr = stderr
	err := command.Run()
	if err == nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.buf.Bytes(), ExitCode: 0}, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.buf.Bytes(), ExitCode: exitError.ExitCode()}, nil
	}
	return Result{}, err
}

// stderrExcerpt reduces the captured toolchain diagnostics to a single-line,
// length-bounded excerpt for the fail-closed error chain: whitespace runs
// collapse to single spaces so no control characters reach the logs, and the
// excerpt carries only the tool's own diagnostic text — never environment,
// argument, or credential material.
func stderrExcerpt(stderr []byte) string {
	text := strings.Join(strings.Fields(string(stderr)), " ")
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > stderrExcerptRunes {
		text = string(runes[:stderrExcerptRunes]) + "…"
	}
	return ": " + text
}

// boundedBuffer is an io.Writer that retains at most the first limit bytes
// written to it; every write reports full consumption so the child process
// never blocks on a discarded tail.
type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

// Write retains the head of p up to the remaining capacity and reports p as
// fully consumed.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		b.buf.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}
