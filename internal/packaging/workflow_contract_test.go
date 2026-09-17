package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
		".github/workflows/ci.yml":                    "hosting-platforms/github/workflows/callers/go/ci.yml",
		".github/workflows/codeql.yml":                "hosting-platforms/github/workflows/callers/go/codeql.yml",
		".github/workflows/dependency-review.yml":     "hosting-platforms/github/workflows/callers/go/dependency-review.yml",
		".github/workflows/canonical-conformance.yml": "hosting-platforms/github/workflows/callers/go/canonical-conformance.yml",
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
		"uses: " + manifest.Home.Repository + "/.github/workflows/reusable-canonical-conformance.yml@" + manifest.Home.SHA,
		`branches: [main, develop, "release/**", "support/**"]`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("the canonical conformance workflow does not contain %q", required)
		}
	}
}

// lifecycleFamilyBinding binds the tenant lifecycle callers to the canonical
// release-lifecycle family of the git-governance home: the exact payload pin
// on the merged home line plus the LF-stable content hash of every caller as
// recorded by the home caller hash record at that pin.
var lifecycleFamilyBinding = struct {
	homeSHA string
	callers map[string]string
}{
	homeSHA: "77da3857d8db3f3567522651750980e087c0a6eb",
	callers: map[string]string{
		"release-control.yml":                "5b339a721f8d31560090eb33f71d434686f17789ef0dc0309fe264b093604d4a",
		"release-reconciliation.yml":         "7fc7eb6efe4a71aceeee2e1c2dec32e25506d4ed59af6f85c36a571c7a6a12da",
		"execute-protected-line-request.yml": "7d166c87338cf6be30acbfcc4f01a807c464c0f0e2d9d0468e79ba229e9053b3",
		"tag-promoted-release.yml":           "578ffd6c5498545c22a3639a66cb49ed1b44964c1eb162e839f470266123bada",
		"publish-release-artifacts.yml":      "a790964db50b6bde5bfaca0b7358951952915cc2183300c97e36e83289521bd2",
		"hotfix-delivery.yml":                "2b5ddf06163f0453465a67dede9adeb0ffcc70ff2733d413f5d997d5a2e60d97",
		"hotfix-propagation.yml":             "476085ba51dbfb6f1d004943c5e603c95a8fa08d99371d58b96014d689f96208",
	},
}

func TestLifecycleCallersBindTheGovernedFamily(t *testing.T) {
	for _, name := range []string{
		"release-control.yml",
		"release-reconciliation.yml",
		"execute-protected-line-request.yml",
		"tag-promoted-release.yml",
		"publish-release-artifacts.yml",
		"hotfix-delivery.yml",
		"hotfix-propagation.yml",
	} {
		want, bound := lifecycleFamilyBinding.callers[name]
		if !bound {
			t.Fatalf("no governed family binding recorded for %q", name)
		}
		path := filepath.Join(".github", "workflows", name)
		if hash := hashRepositoryFile(t, path); hash != want {
			t.Fatalf("the lifecycle caller %s hashes to %s, want the governed family hash %s", path, hash, want)
		}
		content := readRepositoryFile(t, path)
		reference := "uses: t33n-software/git-governance/.github/workflows/reusable-" + name + "@" + lifecycleFamilyBinding.homeSHA
		if !strings.Contains(content, reference) {
			t.Fatalf("the lifecycle caller %s does not pin the governed family at the merged home line", path)
		}
	}
	for _, legacy := range []string{"recover-protected-line-request.yml", "release.yml"} {
		path := filepath.Join(".github", "workflows", legacy)
		if _, err := os.Stat(repositoryPath(path)); !os.IsNotExist(err) {
			t.Fatalf("the legacy lifecycle lane %s must be absent: the governed family carries the bound executor recovery mode and the release delivery", path)
		}
	}
}

func TestLaneWorkflowsBindTheProtectedEnvironments(t *testing.T) {
	lanes := []string{
		"dep-intake-fetch",
		"dep-admission",
		"dep-promotion",
		"dep-revalidation",
		"dep-revocation",
		"dep-evidence-write",
		"dep-evidence-audit",
		"dep-consumer-verification",
	}
	for _, lane := range lanes {
		environmentKey := strings.ToUpper(strings.ReplaceAll(lane, "-", "_"))
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		for _, required := range []string{
			"workflow_dispatch:",
			"environment: " + lane,
			"contents: read",
			"id-token: write",
			"persist-credentials: false",
			"google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
			"workload_identity_provider: ${{ vars." + environmentKey + "_WIF_PROVIDER }}",
			"service_account: ${{ vars." + environmentKey + "_TRIGGER_SERVICE_ACCOUNT }}",
			"WORKLOAD_JOB: ${{ vars." + environmentKey + "_WORKLOAD_JOB }}",
			"gcloud run jobs execute",
			"--wait",
			`--format="value(name)"`,
			"gcloud run jobs executions describe",
			`jq -e '.status.completionTime != null and ((.status.succeededCount // 0) >= 1) and ((.status.failedCount // 0) == 0)'`,
			`"completed: " + .status.completionTime`,
			`"evidence audit pointer: " + .status.logUri`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("lane workflow %s does not contain %q", lane, required)
			}
		}
		for _, forbidden := range []string{
			"t33n-software",
			"pull_request",
			"\n  push:",
			"schedule:",
			"token_format",
			"DEPENDENCY_AUTHORITY_ACCESS_TOKEN",
			"setup-go",
			"go build",
			"go env",
			"curl",
			"DEPENDENCY_AUTHORITY_ZONE",
			"DEPENDENCY_AUTHORITY_ECOSYSTEM",
			"DEPENDENCY_AUTHORITY_ARTIFACT_API",
			"DEPENDENCY_AUTHORITY_UPSTREAM_ENDPOINT",
			"DEPENDENCY_AUTHORITY_APPROVED_ENDPOINT",
			"DEPENDENCY_AUTHORITY_EVIDENCE_REPOSITORY",
			"DEPENDENCY_AUTHORITY_APPROVED_REPOSITORY",
			"DEPENDENCY_AUTHORITY_POLICY_BUNDLE",
			// Documented exception (DA-22): the two scanning lanes carry the
			// scanner identity operation inputs as versioned workflow values;
			// the retired data-plane scanner path forms stay forbidden on every
			// lane, and TestScanningLanesBindTheScannerIdentityOverrides pins
			// the exact exception surface fail-closed.
			"DEPENDENCY_AUTHORITY_SCANNER_TOOL",
			"DEPENDENCY_AUTHORITY_SCANNER_DATABASE=",
			"DEPENDENCY_AUTHORITY_SCAN_CONTENT_ROOT",
			"DEPENDENCY_AUTHORITY_LANE_IDENTITY",
			"DEP_PROBE_",
			"DEP_INTAKE_FETCHER_SERVICE_ACCOUNT",
			"DEP_ADMISSION_CONTROLLER_SERVICE_ACCOUNT",
			"DEP_APPROVED_PROMOTER_SERVICE_ACCOUNT",
			"DEP_REVALIDATION_CONTROLLER_SERVICE_ACCOUNT",
			"DEP_REVOCATION_CONTROLLER_SERVICE_ACCOUNT",
			"DEP_EVIDENCE_WRITER_SERVICE_ACCOUNT",
			"DEP_EVIDENCE_AUDITOR_SERVICE_ACCOUNT",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("lane workflow %s contains %q; lanes are organization-agnostic dispatch-only triggers over the compute control plane and never carry the retired in-lane execution form", lane, forbidden)
			}
		}
		// Regression guard (DA-19): the v2 execution resource carries the
		// status fields under the status wrapper; the retired top-level read
		// paths would report a false failure on a green run and must never
		// return.
		for _, retired := range []string{
			`jq -e '.completionTime != null`,
			`"completed: " + .completionTime`,
			`"evidence audit pointer: " + .logUri`,
		} {
			if strings.Contains(content, retired) {
				t.Fatalf("lane workflow %s contains the retired top-level execution status read path %q; the v2 execution resource carries these fields under the status wrapper", lane, retired)
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

// The pinned scanner channel identities the admission and revalidation lanes
// carry as versioned workflow values (operation inputs, never data-plane
// bindings); a pin bump is a governed pull request, and the lane runtime
// proves every value against the materialized channel artifact.
const (
	scannerToolIdentityBinding     = "DEPENDENCY_AUTHORITY_SCANNER_IDENTITY=osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256:f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be"
	scannerDatabaseIdentityBinding = "DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY=osv-db/go@sha256:474c70f1d32a55dec23f3b45bedc2411298710b0a6add6255f284f6d976909e3"
)

func TestLaneWorkflowsBindTheOperationInputs(t *testing.T) {
	lanes := map[string][]string{
		"dep-intake-fetch": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
		},
		"dep-admission": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
			"DEPENDENCY_AUTHORITY_APPROVAL_TTL=72h",
			scannerToolIdentityBinding, scannerDatabaseIdentityBinding,
		},
		"dep-promotion": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
		},
		"dep-revalidation": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
			scannerToolIdentityBinding, scannerDatabaseIdentityBinding,
		},
		"dep-revocation": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
			"DEPENDENCY_AUTHORITY_REVOCATION_REASON=${{ inputs.reason }}",
		},
		"dep-consumer-verification": {
			"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}", "DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
		},
	}
	for lane, bindings := range lanes {
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		for _, needle := range []string{"inputs:", "module:", "version:", "--update-env-vars="} {
			if !strings.Contains(content, needle) {
				t.Fatalf("lane workflow %s does not declare the dispatch input transport %q", lane, needle)
			}
		}
		for _, binding := range bindings {
			if !strings.Contains(content, binding) {
				t.Fatalf("lane workflow %s does not pass %q as an execution parameter", lane, binding)
			}
		}
	}

	revocation := readRepositoryFile(t, ".github/workflows/dep-revocation.yml")
	if !strings.Contains(revocation, "reason:") || !strings.Contains(revocation, "${{ inputs.reason }}") {
		t.Fatal("the revocation lane does not bind the revocation reason input")
	}

	// The evidence-write lane carries the attested operation event as
	// validated dispatch inputs (the human-gated attestation write); the
	// evidence-audit lane carries the proven subject.
	evidenceWrite := readRepositoryFile(t, ".github/workflows/dep-evidence-write.yml")
	for _, needle := range []string{
		"inputs:",
		"record_type:",
		"subject_lane:",
		"execution:",
		"outcome:",
		"evidence_references:",
		"detail:",
		"--update-env-vars=",
		"DEPENDENCY_AUTHORITY_RECORD_TYPE=${{ inputs.record_type }}",
		"DEPENDENCY_AUTHORITY_SUBJECT_LANE=${{ inputs.subject_lane }}",
		"DEPENDENCY_AUTHORITY_EXECUTION=${{ inputs.execution }}",
		"DEPENDENCY_AUTHORITY_OUTCOME=${{ inputs.outcome }}",
		"DEPENDENCY_AUTHORITY_EVIDENCE_REFERENCES=${{ inputs.evidence_references }}",
		"DEPENDENCY_AUTHORITY_DETAIL=${{ inputs.detail }}",
	} {
		if !strings.Contains(evidenceWrite, needle) {
			t.Fatalf("the evidence-write lane does not bind %q", needle)
		}
	}

	evidenceAudit := readRepositoryFile(t, ".github/workflows/dep-evidence-audit.yml")
	for _, needle := range []string{
		"inputs:",
		"module:",
		"version:",
		"--update-env-vars=",
		"DEPENDENCY_AUTHORITY_MODULE=${{ inputs.module }}",
		"DEPENDENCY_AUTHORITY_VERSION=${{ inputs.version }}",
	} {
		if !strings.Contains(evidenceAudit, needle) {
			t.Fatalf("the evidence-audit lane does not bind %q", needle)
		}
	}
}

// TestScanningLanesBindTheScannerIdentityOverrides pins the documented
// exception of the lane environment sweep: exactly the admission and
// revalidation lanes carry the pinned scanner tool and database identities as
// versioned workflow values, and every other lane carries no scanner binding
// at all.
func TestScanningLanesBindTheScannerIdentityOverrides(t *testing.T) {
	for _, lane := range []string{"dep-admission", "dep-revalidation"} {
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		for _, required := range []string{scannerToolIdentityBinding, scannerDatabaseIdentityBinding} {
			if !strings.Contains(content, required) {
				t.Fatalf("lane workflow %s does not carry the pinned scanner channel identity %q as a versioned workflow value", lane, required)
			}
		}
		stripped := strings.ReplaceAll(content, "DEPENDENCY_AUTHORITY_SCANNER_IDENTITY", "")
		stripped = strings.ReplaceAll(stripped, "DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY", "")
		if strings.Contains(stripped, "DEPENDENCY_AUTHORITY_SCANNER") {
			t.Fatalf("lane workflow %s carries a scanner binding outside the documented identity exception", lane)
		}
	}
	for _, lane := range []string{"dep-intake-fetch", "dep-promotion", "dep-revocation", "dep-evidence-write", "dep-evidence-audit", "dep-consumer-verification"} {
		content := readRepositoryFile(t, ".github/workflows/"+lane+".yml")
		if strings.Contains(content, "DEPENDENCY_AUTHORITY_SCANNER") {
			t.Fatalf("lane workflow %s carries a scanner binding; only the admission and revalidation lanes carry the scanner identity operation inputs", lane)
		}
	}
}

// TestConsumerVerificationCadenceDispatcherBindsTheScheduledForm pins the
// cadence occasion of the consumer verification: the lane itself stays a
// dispatch-only trigger, and the dispatcher fires it on the bound cadence
// through the documented first-class dispatch form — the dispatcher never
// federates, never touches the perimeter, and never carries a data-plane
// reference.
func TestConsumerVerificationCadenceDispatcherBindsTheScheduledForm(t *testing.T) {
	content := readRepositoryFile(t, ".github/workflows/dep-consumer-verification-schedule.yml")
	for _, required := range []string{
		"schedule:",
		"cron:",
		"workflow_dispatch:",
		"permissions:\n      actions: write",
		"vars.DEP_CONSUMER_VERIFICATION_CADENCE_TARGETS",
		"secrets.GITHUB_TOKEN",
		"gh workflow run dep-consumer-verification.yml",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("the consumer verification cadence dispatcher does not contain %q", required)
		}
	}
	for _, forbidden := range []string{
		"google-github-actions/auth",
		"gcloud",
		"WORKLOAD_JOB",
		"DEPENDENCY_AUTHORITY_",
		"t33n-software",
		"pull_request",
		"\n  push:",
		"actions/checkout",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("the consumer verification cadence dispatcher contains %q; it dispatches the lane and never touches the perimeter", forbidden)
		}
	}
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "uses:") {
			continue
		}
		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			t.Fatalf("the cadence dispatcher carries an unpinned action reference %q", line)
		}
		reference := strings.Fields(strings.TrimSpace(parts[1]))[0]
		if len(reference) != 40 || !isHex(reference) {
			t.Fatalf("the cadence dispatcher action %q is not pinned to a full commit SHA", line)
		}
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
		"dependency-consumer-verification-controller",
		"dependency-evidence-write-controller",
		"dependency-evidence-audit-controller",
	} {
		for _, file := range []string{"main.go", "main_test.go"} {
			path := repositoryPath("cmd", controller, file)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing controller file %q: %v", path, err)
			}
		}
	}

	for _, domain := range []string{"admission", "approval", "candidate", "evidence", "quarantine", "revocation", "tooling", "verification"} {
		if _, err := os.Stat(repositoryPath("internal", "dependency", "domain", domain)); err != nil {
			t.Fatalf("missing domain package %q: %v", domain, err)
		}
	}
	for _, application := range []string{"admission", "consumerverification", "evidenceaudit", "evidencewrite", "intake", "promotion", "revalidation", "revocation"} {
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
		repositoryPath("internal", "dependency", "adapters", "outbound", "consumercontract"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "evidence"),
		repositoryPath("internal", "dependency", "adapters", "outbound", "tooling"),
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
	} {
		if !strings.Contains(quality, required) {
			t.Fatalf("git-governance.quality.json does not contain %q", required)
		}
	}

	var qualityConfig struct {
		Gates []struct {
			Name    string   `json:"name"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"gates"`
		Project struct {
			Binaries []struct {
				Package string `json:"package"`
			} `json:"binaries"`
		} `json:"project"`
	}
	if err := json.Unmarshal([]byte(quality), &qualityConfig); err != nil {
		t.Fatalf("git-governance.quality.json is not valid JSON: %v", err)
	}
	if len(qualityConfig.Gates) != 1 {
		t.Fatalf("git-governance.quality.json carries %d gates, want exactly the canonical gate chain", len(qualityConfig.Gates))
	}
	if qualityConfig.Gates[0].Name != "dependency-authority-source-quality" ||
		qualityConfig.Gates[0].Command != "go" ||
		!slices.Equal(qualityConfig.Gates[0].Args, []string{"tool", "-modfile", "tools/go.mod", "quality-gate"}) {
		t.Fatal("the gate does not invoke the canonical gate chain through the tooling module pin")
	}
	if len(qualityConfig.Project.Binaries) != 8 {
		t.Fatalf("the project binaries must carry the eight lane controllers, got %d", len(qualityConfig.Project.Binaries))
	}
	for _, binary := range qualityConfig.Project.Binaries {
		if !strings.HasPrefix(binary.Package, "./cmd/dependency-") {
			t.Fatalf("unexpected project binary %q", binary.Package)
		}
	}
	for _, forbidden := range []string{`"./cmd/build"`, `"./cmd/check-coverage"`, `"defaults"`} {
		if strings.Contains(quality, forbidden) {
			t.Fatalf("git-governance.quality.json still contains %s", forbidden)
		}
	}
	for _, chainCopy := range []string{"cmd/build", "cmd/check-coverage"} {
		if _, err := os.Stat(repositoryPath(filepath.FromSlash(chainCopy))); !os.IsNotExist(err) {
			t.Fatalf("the repo-local gate chain copy %s must not exist", chainCopy)
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
		"github.com/t33n-software/git-governance/cmd/git-governance",
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

func TestControllerImageSubstrateBindsTheGovernedBuildForm(t *testing.T) {
	dockerfile := readRepositoryFile(t, "Dockerfile")
	for _, required := range []string{
		"FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab",
		"ARG CONTROLLER",
		"COPY .build/controller-images/${CONTROLLER} /controller",
		"ARG TOOLCHAIN=none",
		"COPY .build/toolchain/${TOOLCHAIN} /toolchain/",
		"USER 65532:65532",
		`ENTRYPOINT ["/controller"]`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("Dockerfile does not bind %q", required)
		}
	}
	for _, forbidden := range []string{"# syntax", "latest", "AS builder", "go build"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Fatalf("Dockerfile contains %q; the substrate is pure packaging on the digest-pinned minimal non-root runtime", forbidden)
		}
	}

	runbook := readRepositoryFile(t, filepath.Join("docs", "operations", "controller-image-substrate.md"))
	for _, controller := range []string{
		"dependency-intake-controller",
		"dependency-admission-controller",
		"dependency-promotion-controller",
		"dependency-revalidation-controller",
		"dependency-revocation-controller",
		"dependency-consumer-verification-controller",
		"dependency-evidence-write-controller",
		"dependency-evidence-audit-controller",
	} {
		if !strings.Contains(runbook, controller) {
			t.Fatalf("the controller image runbook does not bind %q", controller)
		}
	}
	for _, required := range []string{
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
		"-trimpath",
		`"-s -w"`,
		"sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab",
		"staging-controller-images",
		"release-controller-images",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("the controller image runbook does not bind %q", required)
		}
	}

	readme := readRepositoryFile(t, "README.md")
	if !strings.Contains(readme, "Dockerfile") {
		t.Fatal("README.md does not document the root Dockerfile in the repository layout")
	}

	traceability := readRepositoryFile(t, filepath.Join("docs", "TRACEABILITY.md"))
	if !strings.Contains(traceability, "DA-16") {
		t.Fatal("TRACEABILITY.md does not contain DA-16")
	}
}

// TestGoDistributionPinBindsTheToolchainDirective binds the distribution pin
// of the toolchain-bearing image variant (GO-SCF-019, GO-AT-32): the pin is a
// versioned product-source file at the repository root whose version is
// fail-closed coupled to the toolchain directive of go.mod, whose publisher
// checksum is well-formed, and whose staging form is bound in the substrate
// runbook — never an instance binding, never a floating download.
func TestGoDistributionPinBindsTheToolchainDirective(t *testing.T) {
	var pin struct {
		SchemaVersion int `json:"schemaVersion"`
		Distribution  struct {
			Version                 string `json:"version"`
			Artifact                string `json:"artifact"`
			Checksum                string `json:"checksum"`
			SizeBytes               int64  `json:"sizeBytes"`
			PublisherReleaseChannel string `json:"publisherReleaseChannel"`
			ProvenAt                string `json:"provenAt"`
		} `json:"distribution"`
	}
	if err := json.Unmarshal([]byte(readRepositoryFile(t, "go-distribution-pin.json")), &pin); err != nil {
		t.Fatalf("go-distribution-pin.json is not valid JSON: %v", err)
	}
	if pin.SchemaVersion != 1 {
		t.Fatalf("go-distribution-pin.json carries schemaVersion %d, want 1", pin.SchemaVersion)
	}

	directive := goModToolchainDirective(t)
	if pin.Distribution.Version != directive {
		t.Fatalf("the distribution pin version %q deviates from the toolchain directive %q of go.mod", pin.Distribution.Version, directive)
	}
	if want := directive + ".linux-amd64.tar.gz"; pin.Distribution.Artifact != want {
		t.Fatalf("the distribution pin artifact %q does not match the pinned version form %q", pin.Distribution.Artifact, want)
	}
	checksum, found := strings.CutPrefix(pin.Distribution.Checksum, "sha256:")
	if !found || len(checksum) != 64 || !isHex(checksum) {
		t.Fatalf("the distribution pin checksum %q is not the well-formed sha256:<64 hex> form", pin.Distribution.Checksum)
	}
	if pin.Distribution.SizeBytes <= 0 {
		t.Fatalf("the distribution pin carries no positive size evidence, got %d", pin.Distribution.SizeBytes)
	}
	if pin.Distribution.PublisherReleaseChannel != "https://go.dev/dl/" {
		t.Fatalf("the distribution pin binds publisher release channel %q, want the publisher release channel of the Go distribution", pin.Distribution.PublisherReleaseChannel)
	}
	if _, err := time.Parse("2006-01-02", pin.Distribution.ProvenAt); err != nil {
		t.Fatalf("the distribution pin provenance date %q is not the YYYY-MM-DD form: %v", pin.Distribution.ProvenAt, err)
	}

	runbook := readRepositoryFile(t, filepath.Join("docs", "operations", "controller-image-substrate.md"))
	for _, required := range []string{
		"go-distribution-pin.json",
		".build/toolchain/go/",
		"against the pinned publisher checksum",
		"bootstrap era",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("the controller image runbook does not bind the distribution pin staging form %q", required)
		}
	}
	// Regression guard (DA-33): the distribution identity is a product-source
	// pin coupled to the toolchain directive; the retired instance-binding
	// form must never return.
	if strings.Contains(runbook, "organization instance") {
		t.Fatal("the controller image runbook still carries the retired instance-binding form of the distribution pin")
	}

	readme := readRepositoryFile(t, "README.md")
	if !strings.Contains(readme, "go-distribution-pin.json") {
		t.Fatal("README.md does not document the distribution pin in the repository layout")
	}

	traceability := readRepositoryFile(t, filepath.Join("docs", "TRACEABILITY.md"))
	if !strings.Contains(traceability, "DA-33") {
		t.Fatal("TRACEABILITY.md does not contain DA-33")
	}
}

// TestOperationsCarryTheWorkloadImageExceptionWindow binds the exception
// window boilerplate of the workload-image lifecycle convention: every
// workload-image-producing project carries the only human deletion path as a
// placeholder-driven script on its operations surface — the proven window
// form (the role-content proof, the live-bound guard, the registry-class
// guard, the grant with its read-back proof, the propagation window, the
// complete delete, the inventory arbiter and the finally hardening) — and
// never a concrete organization value.
func TestOperationsCarryTheWorkloadImageExceptionWindow(t *testing.T) {
	script := readRepositoryFile(t, filepath.Join("docs", "operations", "Invoke-WorkloadImageExceptionWindow.ps1"))
	for _, required := range []string{
		"$OperatorMember",
		"$ControlProjectId",
		"$Region",
		"$RepositoryName",
		"$ImageName",
		"$Digest",
		"$InstanceCheckoutPath",
		"roles/artifactregistry.admin",
		"artifactregistry.versions.delete",
		"artifactregistry.dockerimages.list",
		"staging-controller-images",
		"release-controller-images",
		"--delete-tags",
		"--format=none",
		"workload-jobs.yaml",
		`--format="value(account)"`,
		`--format="value(includedPermissions)"`,
		"ConvertFrom-Json",
		"Start-Sleep",
		"finally",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("the workload-image exception window script does not bind %q", required)
		}
	}
	for _, forbidden := range []string{
		"t33n",
		"test-software",
		"test-go-builder",
		"europe-west3",
		"dep-control",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the workload-image exception window script carries the concrete organization value %q; the boilerplate binds every zone, project, registry and identity as a variable", forbidden)
		}
	}
	// A 64-hex run after the digest marker is a concrete digest, never a
	// placeholder: the boilerplate carries the digest as a head variable only.
	rest := script
	for {
		index := strings.Index(rest, "sha256:")
		if index < 0 {
			break
		}
		rest = rest[index+len("sha256:"):]
		run := 0
		for run < len(rest) && isHex(rest[run:run+1]) {
			run++
		}
		if run >= 64 {
			t.Fatal("the workload-image exception window script carries a concrete digest; the boilerplate binds the digest as a head variable")
		}
	}
}

// goModToolchainDirective extracts the version token of the toolchain
// directive of go.mod; the distribution pin is coupled to exactly this token.
func goModToolchainDirective(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(readRepositoryFile(t, "go.mod"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "toolchain" {
			return fields[1]
		}
	}
	t.Fatal("go.mod does not carry a toolchain directive")
	return ""
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
