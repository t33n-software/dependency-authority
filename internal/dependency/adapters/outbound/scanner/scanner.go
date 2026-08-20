// Package scanner implements the admission.Scanner port: executing the pinned
// OSV-Scanner tool against the materialized candidate content with the local,
// snapshot-based vulnerability database. The adapter never downloads
// vulnerability data at scan time; the isolated lane provides the snapshot.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// databaseLocationEnv names the environment variable that points OSV-Scanner
// at the local snapshot database directory.
const databaseLocationEnv = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

// conservativeScore is the fail-closed severity for a vulnerability without a
// computable CVSS v3 vector: the policy sees the maximum possible impact
// instead of an unproven pass.
const conservativeScore = 10.0

// Result carries the process outcome of a scan execution.
type Result struct {
	Stdout   []byte
	ExitCode int
}

// Runner executes the pinned tool. ExecRunner satisfies it in production.
type Runner func(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error)

// OSV is the OSV-Scanner adapter.
type OSV struct {
	tool        string
	database    string
	contentRoot string
	run         Runner
}

// NewOSV constructs the scanner adapter and fails closed on empty tool,
// database, or content-root bindings or a nil runner.
func NewOSV(tool string, database string, contentRoot string, run Runner) (OSV, error) {
	if strings.TrimSpace(tool) == "" {
		return OSV{}, errors.New("scanner tool path must not be empty")
	}
	if strings.TrimSpace(database) == "" {
		return OSV{}, errors.New("scanner database directory must not be empty")
	}
	if strings.TrimSpace(contentRoot) == "" {
		return OSV{}, errors.New("scanner content root must not be empty")
	}
	if run == nil {
		return OSV{}, errors.New("scanner runner must not be nil")
	}
	return OSV{tool: tool, database: database, contentRoot: contentRoot, run: run}, nil
}

// Scan executes the pinned tool against the materialized candidate content
// and reduces the findings to the admission scan result. License findings are
// not produced here; policy evaluation owns them (ADR-0002).
func (o OSV) Scan(ctx context.Context, subject candidate.Candidate) (admission.ScanResult, error) {
	dir, err := o.contentPath(subject)
	if err != nil {
		return admission.ScanResult{}, err
	}

	result, err := o.run(ctx, dir, []string{databaseLocationEnv + "=" + o.database}, o.tool, "scan", "--offline", "--format", "json", ".")
	if err != nil {
		return admission.ScanResult{}, fmt.Errorf("execute scanner: %w", err)
	}
	if result.ExitCode != 0 && result.ExitCode != 1 {
		return admission.ScanResult{}, fmt.Errorf("scanner exited with code %d", result.ExitCode)
	}

	output, err := decode(result.Stdout)
	if err != nil {
		return admission.ScanResult{}, fmt.Errorf("decode scanner output: %w", err)
	}
	return admission.ScanResult{MaxCVSS: maxSeverity(output), Licenses: nil}, nil
}

// contentPath binds the candidate identity to its materialization directory
// and rejects any path that escapes the configured content root.
func (o OSV) contentPath(subject candidate.Candidate) (string, error) {
	root := filepath.Clean(o.contentRoot)
	relative := filepath.Join(string(subject.Ecosystem()), filepath.FromSlash(subject.Name())+"@"+subject.Version())
	full := filepath.Join(root, relative)
	if full != root && !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("candidate content path %q escapes the materialization root", full)
	}
	return full, nil
}

// scanOutput mirrors the OSV-Scanner JSON result document.
type scanOutput struct {
	Results []struct {
		Packages []struct {
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// decode parses the scanner JSON document.
func decode(content []byte) (scanOutput, error) {
	var output scanOutput
	if err := json.Unmarshal(content, &output); err != nil {
		return scanOutput{}, err
	}
	return output, nil
}

// maxSeverity reduces every vulnerability to its computable CVSS v3 base
// score and returns the maximum. A vulnerability without a computable vector
// contributes the conservative maximum, never an unproven pass.
func maxSeverity(output scanOutput) float64 {
	maxScore := 0.0
	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			for _, vulnerability := range pkg.Vulnerabilities {
				score := vulnerabilityScore(vulnerability.Severity)
				if score > maxScore {
					maxScore = score
				}
			}
		}
	}
	return maxScore
}

// vulnerabilityScore computes the vulnerability score from its CVSS v3
// severity vectors. Without a computable vector the conservative maximum
// applies.
func vulnerabilityScore(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) float64 {
	best := -1.0
	for _, severity := range severities {
		if severity.Type != "CVSS_V3" {
			continue
		}
		score, err := cvss3BaseScore(severity.Score)
		if err != nil {
			continue
		}
		if score > best {
			best = score
		}
	}
	if best < 0 {
		return conservativeScore
	}
	return best
}

// ExecRunner executes the pinned tool as a child process. A non-zero exit
// code is a result, not an error; only a failed start is an error.
func ExecRunner(ctx context.Context, dir string, env []string, name string, args ...string) (Result, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err := command.Run()
	if err == nil {
		return Result{Stdout: stdout.Bytes(), ExitCode: 0}, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return Result{Stdout: stdout.Bytes(), ExitCode: exitError.ExitCode()}, nil
	}
	return Result{}, err
}
