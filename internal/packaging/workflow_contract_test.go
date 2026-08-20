package packaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceWorkflowsCoverEverySharedLine(t *testing.T) {
	for _, workflow := range []string{
		".github/workflows/ci.yml",
		".github/workflows/codeql.yml",
		".github/workflows/dependency-review.yml",
	} {
		content := readRepositoryFile(t, workflow)
		for _, required := range []string{"main", "develop", "release/**", "support/**"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not cover the shared line %q; the pre-positioned shared-line rulesets bind every future matching ref from its first commit", workflow, required)
			}
		}
	}

	ci := readRepositoryFile(t, ".github/workflows/ci.yml")
	for _, required := range []string{
		"Quality gates (linux-amd64)",
		"go run -mod=readonly ./cmd/build",
		"actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0",
		"actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c",
	} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI workflow does not contain %q", required)
		}
	}

	dependencyReview := readRepositoryFile(t, ".github/workflows/dependency-review.yml")
	for _, required := range []string{
		"Dependency admission review",
		"fail-on-severity: low",
		"fail-on-scopes: runtime,development,unknown",
		"actions/dependency-review-action@2031cfc080254a8a887f58cffee85186f0e49e48",
	} {
		if !strings.Contains(dependencyReview, required) {
			t.Fatalf("dependency review workflow does not contain %q", required)
		}
	}
}

func TestLaneWorkflowsBindTheProtectedEnvironments(t *testing.T) {
	lanes := map[string]string{
		"dep-intake-fetch":   "dependency-intake-controller",
		"dep-admission":      "dependency-admission-controller",
		"dep-promotion":      "dependency-promotion-controller",
		"dep-revalidation":   "dependency-revalidation-controller",
		"dep-revocation":     "dependency-revocation-controller",
		"dep-evidence-write": "",
		"dep-evidence-audit": "",
	}
	for lane, controller := range lanes {
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		for _, required := range []string{
			"workflow_dispatch:",
			"environment: " + lane,
			"id-token: write",
			"google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("lane workflow %s does not contain %q", lane, required)
			}
		}
		if controller != "" && !strings.Contains(content, "./cmd/"+controller) {
			t.Fatalf("lane workflow %s does not build %q", lane, controller)
		}
		for _, forbidden := range []string{"t33n-software", "pull_request", "\n  push:", "schedule:"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("lane workflow %s contains %q; lanes are organization-agnostic and dispatch-only", lane, forbidden)
			}
		}
		for _, line := range strings.Split(content, "\n") {
			if !strings.Contains(line, "uses:") {
				continue
			}
			parts := strings.SplitN(line, "@", 2)
			if len(parts) != 2 {
				t.Fatalf("lane workflow %s carries an unpinned action reference %q", lane, line)
			}
			reference := strings.Fields(strings.TrimSpace(parts[1]))[0]
			if len(reference) != 40 || !isHex(reference) {
				t.Fatalf("lane workflow %s action %q is not pinned to a full commit SHA", lane, line)
			}
		}
	}
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func TestOrganizationRulesetAdoptionHasNoLocalLegacyDefinitions(t *testing.T) {
	if _, err := os.Stat(repositoryPath("docs", "hosting-platforms")); !os.IsNotExist(err) {
		t.Fatalf("legacy ruleset location must not exist")
	}

	conventions := readRepositoryFile(t, filepath.Join("docs", "conventions", "hosting-plattform", "github", "rule-sets", "README.md"))
	for _, required := range []string{
		"git-governance",
		"quality-gates=linux-only",
		"~ALL",
	} {
		if !strings.Contains(conventions, required) {
			t.Fatalf("rule-set conventions README does not contain %q", required)
		}
	}
}

func TestGovernanceDocumentationPreservesCoreInstanceAndTenantBoundaries(t *testing.T) {
	for _, path := range []string{
		"README.md",
		"docs/architecture/ADR-0001-DEPENDENCY-AUTHORITY.md",
		"docs/development/VERIFICATION.md",
	} {
		content := strings.ToLower(readRepositoryFile(t, path))
		for _, required := range []string{"core", "instance", "tenant"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not document %q boundary", path, required)
			}
		}
	}

	adr := readRepositoryFile(t, "docs/architecture/ADR-0001-DEPENDENCY-AUTHORITY.md")
	for _, required := range []string{
		"never contains concrete organization",
		"never contains tenant",
		"control",
		"intake",
		"quarantine",
		"approved",
		"evidence",
	} {
		if !strings.Contains(adr, required) {
			t.Fatalf("ADR does not contain %q", required)
		}
	}
}

func TestControllerAndDomainLayoutIsComplete(t *testing.T) {
	for _, controller := range []string{
		"dependency-intake-controller",
		"dependency-admission-controller",
		"dependency-promotion-controller",
		"dependency-revalidation-controller",
		"dependency-revocation-controller",
	} {
		for _, file := range []string{"main.go", "main_test.go"} {
			path := repositoryPath("cmd", controller, file)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing controller file %q: %v", path, err)
			}
		}
	}

	for _, domain := range []string{"admission", "approval", "candidate", "evidence", "quarantine", "revocation"} {
		if _, err := os.Stat(repositoryPath("internal", "dependency", "domain", domain)); err != nil {
			t.Fatalf("missing domain package %q: %v", domain, err)
		}
	}
	for _, application := range []string{"admission", "intake", "promotion", "revalidation", "revocation"} {
		if _, err := os.Stat(repositoryPath("internal", "dependency", "application", application)); err != nil {
			t.Fatalf("missing application package %q: %v", application, err)
		}
	}
	for _, path := range []string{
		repositoryPath("internal", "dependency", "adapters", "inbound", "config"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "upstream"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "policy"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "scanner"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "artifactregistry"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "evidence"),
		repositoryPath("internal", "dependency", "bootstrap"),
		repositoryPath("test", "contract"),
		repositoryPath("test", "integration"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing architecture path %q: %v", path, err)
		}
	}
}

func TestModuleIdentityAndQualityContract(t *testing.T) {
	goMod := readRepositoryFile(t, "go.mod")
	for _, required := range []string{
		"module github.com/t33n-software/dependency-authority",
		"go 1.26",
		"toolchain go1.26.6",
	} {
		if !strings.Contains(goMod, required) {
			t.Fatalf("go.mod does not contain %q", required)
		}
	}

	quality := readRepositoryFile(t, "git-governance.quality.json")
	for _, required := range []string{
		"dependency-authority-source-quality",
		"./cmd/build",
	} {
		if !strings.Contains(quality, required) {
			t.Fatalf("git-governance.quality.json does not contain %q", required)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	if !strings.Contains(lefthook, "go run -mod=readonly ./cmd/build") {
		t.Fatal("lefthook.yml does not run the source-quality gate")
	}
}

func TestGoToolchainAndBuildToolingContract(t *testing.T) {
	toolsMod := readRepositoryFile(t, filepath.Join("tools", "go.mod"))
	for _, required := range []string{
		"module github.com/t33n-software/dependency-authority/tools",
		"toolchain go1.26.6",
		"github.com/evilmartians/lefthook/v2",
		"golang.org/x/vuln/cmd/govulncheck",
		"honnef.co/go/tools/cmd/staticcheck",
	} {
		if !strings.Contains(toolsMod, required) {
			t.Fatalf("tools/go.mod does not contain %q", required)
		}
	}
	if _, err := os.Stat(repositoryPath("tools", "go.sum")); err != nil {
		t.Fatalf("tools/go.sum is missing: %v", err)
	}

	ci := readRepositoryFile(t, ".github/workflows/ci.yml")
	for _, required := range []string{
		`go-version: "1.26.6"`,
		`test "$(go env GOVERSION)" = "go1.26.6"`,
		"schedule:",
		"cron:",
	} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI workflow does not contain %q", required)
		}
	}

	codeql := readRepositoryFile(t, ".github/workflows/codeql.yml")
	for _, required := range []string{
		`go-version: "1.26.6"`,
		`test "$(go env GOVERSION)" = "go1.26.6"`,
	} {
		if !strings.Contains(codeql, required) {
			t.Fatalf("CodeQL workflow does not contain %q", required)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	for _, required := range []string{
		"commit-msg:",
		`git-governance --interactive never commit validate --message-file "{1}"`,
		"pre-push:",
		"go run -mod=readonly ./cmd/build",
	} {
		if !strings.Contains(lefthook, required) {
			t.Fatalf("lefthook.yml does not contain %q", required)
		}
	}

	traceability := readRepositoryFile(t, filepath.Join("docs", "TRACEABILITY.md"))
	if !strings.Contains(traceability, "DA-3") {
		t.Fatal("TRACEABILITY.md does not contain DA-3")
	}
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(repositoryPath(filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return string(content)
}

func repositoryPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}
