package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bindingManifest mirrors the tenant binding manifest (repo-bindings/v1) for
// the self-consistency proofs of the canonical adoption. The home-side proof
// against the canonical masters is owned by the verify-canonical tool; these
// tests bind the tenant files to the manifest.
type bindingManifest struct {
	Home struct {
		Repository string `json:"repository"`
		SHA        string `json:"sha"`
	} `json:"home"`
	Callers []struct {
		File   string `json:"file"`
		Master string `json:"master"`
		SHA256 string `json:"sha256"`
	} `json:"callers"`
	Files struct {
		Lefthook      fileBinding `json:"lefthook"`
		Gitattributes fileBinding `json:"gitattributes"`
		Gitignore     fileBinding `json:"gitignore"`
		Dependabot    fileBinding `json:"dependabot"`
	} `json:"files"`
	Codeowners struct {
		Path         string `json:"path"`
		DefaultOwner string `json:"defaultOwner"`
	} `json:"codeowners"`
}

type fileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func readBindingManifest(t *testing.T) bindingManifest {
	t.Helper()
	var manifest bindingManifest
	if err := json.Unmarshal([]byte(readRepositoryFile(t, "repo-bindings.json")), &manifest); err != nil {
		t.Fatalf("repo-bindings.json is not valid JSON: %v", err)
	}
	if manifest.Home.Repository != "t33n-software/repository-governance" {
		t.Fatalf("the manifest binds home %q", manifest.Home.Repository)
	}
	return manifest
}

// hashRepositoryFile hashes the LF-normalized repository file; the canonical
// .gitattributes makes the checkout LF, and the normalization keeps the
// derivation tolerant as the second line of defense.
func hashRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	normalized := strings.ReplaceAll(readRepositoryFile(t, path), "\r\n", "\n")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalCallersMatchTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	want := map[string]string{
		".github/workflows/ci.yml":                "hosting-platforms/github/workflows/callers/go/ci.yml",
		".github/workflows/codeql.yml":            "hosting-platforms/github/workflows/callers/go/codeql.yml",
		".github/workflows/dependency-review.yml": "hosting-platforms/github/workflows/callers/go/dependency-review.yml",
	}
	if len(manifest.Callers) != len(want) {
		t.Fatalf("the manifest carries %d callers, want %d", len(manifest.Callers), len(want))
	}
	for _, caller := range manifest.Callers {
		master, found := want[caller.File]
		if !found {
			t.Fatalf("the manifest carries an unexpected caller %q", caller.File)
		}
		if caller.Master != master {
			t.Fatalf("caller %q binds master %q, want %q", caller.File, caller.Master, master)
		}
		if hash := hashRepositoryFile(t, caller.File); hash != caller.SHA256 {
			t.Fatalf("the tenant caller %s hashes to %s, want the bound %s", caller.File, hash, caller.SHA256)
		}
		content := readRepositoryFile(t, caller.File)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the tenant caller %s does not reference a home payload", caller.File)
		}
		if !strings.Contains(content, "@"+manifest.Home.SHA) {
			t.Fatalf("the tenant caller %s does not pin the bound home SHA", caller.File)
		}
		if !strings.Contains(content, `branches: [main, develop, "release/**", "support/**"]`) {
			t.Fatalf("the tenant caller %s does not cover every shared line", caller.File)
		}
	}
}

func TestCanonicalFileFamilyMatchesTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	for _, topic := range []fileBinding{
		manifest.Files.Lefthook,
		manifest.Files.Gitattributes,
		manifest.Files.Dependabot,
	} {
		if hash := hashRepositoryFile(t, topic.Path); hash != topic.SHA256 {
			t.Fatalf("the canonical file %s hashes to %s, want the bound %s", topic.Path, hash, topic.SHA256)
		}
	}
	// The gitignore topic is prefix-mode in the home verifier: the canonical
	// core is a verbatim prefix and project additions live below the mark.
	gitignore := readRepositoryFile(t, manifest.Files.Gitignore.Path)
	if !strings.HasSuffix(gitignore, "# -- project additions below this line --\n") {
		t.Fatal("the gitignore does not carry the canonical core with the project-block mark")
	}

	codeowners := readRepositoryFile(t, manifest.Codeowners.Path)
	if !strings.Contains(codeowners, "* "+manifest.Codeowners.DefaultOwner) {
		t.Fatalf("the ownership file does not bind the default owner %q", manifest.Codeowners.DefaultOwner)
	}
}

func TestConformanceWorkflowBindsTheVerifier(t *testing.T) {
	manifest := readBindingManifest(t)
	content := readRepositoryFile(t, ".github/workflows/canonical-conformance.yml")
	for _, required := range []string{
		"permissions: {}",
		"name: Canonical conformance",
		"uses: " + manifest.Home.Repository + "/.github/actions/verify-canonical-files@" + manifest.Home.SHA,
		`branches: [main, develop, "release/**", "support/**"]`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("the canonical conformance workflow does not contain %q", required)
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

func TestLaneWorkflowsBindTheOperationInputs(t *testing.T) {
	lanes := map[string][]string{
		"dep-intake-fetch": {
			"DEPENDENCY_AUTHORITY_MODULE", "DEPENDENCY_AUTHORITY_VERSION",
		},
		"dep-admission": {
			"DEPENDENCY_AUTHORITY_MODULE", "DEPENDENCY_AUTHORITY_VERSION",
			"DEPENDENCY_AUTHORITY_LANE_IDENTITY", "DEPENDENCY_AUTHORITY_SCANNER_IDENTITY",
			"DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY", "DEPENDENCY_AUTHORITY_APPROVAL_TTL",
		},
		"dep-promotion": {
			"DEPENDENCY_AUTHORITY_MODULE", "DEPENDENCY_AUTHORITY_VERSION",
		},
		"dep-revalidation": {
			"DEPENDENCY_AUTHORITY_MODULE", "DEPENDENCY_AUTHORITY_VERSION",
			"DEPENDENCY_AUTHORITY_SCANNER_IDENTITY", "DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY",
		},
		"dep-revocation": {
			"DEPENDENCY_AUTHORITY_MODULE", "DEPENDENCY_AUTHORITY_VERSION",
			"DEPENDENCY_AUTHORITY_LANE_IDENTITY", "DEPENDENCY_AUTHORITY_REVOCATION_REASON",
		},
	}
	for lane, required := range lanes {
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		for _, needle := range []string{"inputs:", "module:", "version:", "${{ inputs.module }}", "${{ inputs.version }}"} {
			if !strings.Contains(content, needle) {
				t.Fatalf("lane workflow %s does not declare the dispatch input %q", lane, needle)
			}
		}
		for _, binding := range required {
			if !strings.Contains(content, binding+":") {
				t.Fatalf("lane workflow %s does not bind %q", lane, binding)
			}
		}
	}

	revocation := readRepositoryFile(t, ".github/workflows/dep-revocation.yml")
	if !strings.Contains(revocation, "reason:") || !strings.Contains(revocation, "${{ inputs.reason }}") {
		t.Fatal("the revocation lane does not bind the revocation reason input")
	}
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
		`"schemaVersion": 4`,
		`"language": "go"`,
		`"version": "1.26.6"`,
		`"extends": []`,
		"dependency-authority-source-quality",
		"./cmd/build",
	} {
		if !strings.Contains(quality, required) {
			t.Fatalf("git-governance.quality.json does not contain %q", required)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	if !strings.Contains(lefthook, "git-governance --interactive never validate pre-push --remote") {
		t.Fatal("lefthook.yml does not bind the canonical pre-push validation")
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
		"github.com/t33n-software/go-quality-authority/cmd/quality-gate",
		"github.com/t33n-software/go-quality-authority/cmd/check-coverage",
		"github.com/t33n-software/repository-governance/cmd/verify-canonical",
	} {
		if !strings.Contains(toolsMod, required) {
			t.Fatalf("tools/go.mod does not contain %q", required)
		}
	}
	if _, err := os.Stat(repositoryPath("tools", "go.sum")); err != nil {
		t.Fatalf("tools/go.sum is missing: %v", err)
	}

	manifest := readBindingManifest(t)
	for _, caller := range []string{"ci.yml", "codeql.yml"} {
		content := readRepositoryFile(t, ".github/workflows/"+caller)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the caller %s does not reference a home payload", caller)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	for _, required := range []string{
		"commit-msg:",
		`git-governance --interactive never commit validate --message-file "{1}"`,
		"pre-push:",
		`git-governance --interactive never validate pre-push --remote "{1}"`,
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
