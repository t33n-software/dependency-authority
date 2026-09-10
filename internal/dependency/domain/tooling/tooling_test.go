package tooling

import (
	"strings"
	"testing"
)

// testDigestForm is a syntactically valid sha256 reference digest for the
// grammar tests; it carries no real content binding.
var testDigestForm = "sha256:" + strings.Repeat("a", 64)

func TestParseToolBindsTheValidForm(t *testing.T) {
	identity, err := ParseTool("osv-scanner/v2.5.1/osv-scanner_linux_amd64@" + testDigestForm)
	if err != nil {
		t.Fatalf("ParseTool() error = %v", err)
	}
	if identity.Kind() != KindTool {
		t.Fatalf("Kind() = %v, want KindTool", identity.Kind())
	}
	if identity.Path() != "osv-scanner/v2.5.1/osv-scanner_linux_amd64" {
		t.Fatalf("Path() = %q", identity.Path())
	}
	if identity.Digest() != testDigestForm {
		t.Fatalf("Digest() = %q", identity.Digest())
	}
	if identity.DigestHex() != strings.Repeat("a", 64) {
		t.Fatalf("DigestHex() = %q", identity.DigestHex())
	}
	if identity.String() != "osv-scanner/v2.5.1/osv-scanner_linux_amd64@"+testDigestForm {
		t.Fatalf("String() = %q", identity.String())
	}
	if !identity.Valid() {
		t.Fatal("Valid() = false, want true")
	}
}

func TestParseToolRejectsDeviations(t *testing.T) {
	for name, value := range map[string]string{
		"wrong tool name":   "other/v2.5.1/osv-scanner_linux_amd64@" + testDigestForm,
		"two segments":      "osv-scanner/v2.5.1@" + testDigestForm,
		"four segments":     "osv-scanner/v2.5.1/osv-scanner_linux_amd64/extra@" + testDigestForm,
		"unpinned version":  "osv-scanner/2.5.1/osv-scanner_linux_amd64@" + testDigestForm,
		"partial version":   "osv-scanner/v2.5/osv-scanner_linux_amd64@" + testDigestForm,
		"empty version":     "osv-scanner//osv-scanner_linux_amd64@" + testDigestForm,
		"asset without os":  "osv-scanner/v2.5.1/osv-scanner@" + testDigestForm,
		"foreign asset":     "osv-scanner/v2.5.1/other_linux_amd64@" + testDigestForm,
		"missing separator": "osv-scanner/v2.5.1/osv-scanner_linux_amd64",
		"empty path":        "@" + testDigestForm,
		"short digest":      "osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256:aa",
		"uppercase digest":  "osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256:" + strings.Repeat("A", 64),
		"no algorithm":      "osv-scanner/v2.5.1/osv-scanner_linux_amd64@" + strings.Repeat("a", 64),
		"double separator":  "osv-scanner/v2.5.1/osv-scanner_linux_amd64@" + testDigestForm + "@extra",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTool(value); err == nil {
				t.Fatalf("ParseTool(%q) error = nil, want rejection", value)
			}
		})
	}
}

func TestParseDatabaseBindsTheValidForm(t *testing.T) {
	identity, err := ParseDatabase("osv-db/go@" + testDigestForm)
	if err != nil {
		t.Fatalf("ParseDatabase() error = %v", err)
	}
	if identity.Kind() != KindDatabase {
		t.Fatalf("Kind() = %v, want KindDatabase", identity.Kind())
	}
	if identity.Path() != "osv-db/go" {
		t.Fatalf("Path() = %q", identity.Path())
	}
	if identity.String() != "osv-db/go@"+testDigestForm {
		t.Fatalf("String() = %q", identity.String())
	}
	if !identity.Valid() {
		t.Fatal("Valid() = false, want true")
	}
}

func TestParseDatabaseRejectsDeviations(t *testing.T) {
	for name, value := range map[string]string{
		"wrong snapshot name": "other/go@" + testDigestForm,
		"one segment":         "osv-db@" + testDigestForm,
		"three segments":      "osv-db/go/extra@" + testDigestForm,
		"empty ecosystem":     "osv-db/@" + testDigestForm,
		"unknown ecosystem":   "osv-db/bogus@" + testDigestForm,
		"uppercase ecosystem": "osv-db/GO@" + testDigestForm,
		"missing separator":   "osv-db/go",
		"bad digest":          "osv-db/go@sha256:zz",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDatabase(value); err == nil {
				t.Fatalf("ParseDatabase(%q) error = nil, want rejection", value)
			}
		})
	}
}

func TestParseBundleBindsTheValidForm(t *testing.T) {
	identity, err := ParseBundle("dependency-policy/v1@" + testDigestForm)
	if err != nil {
		t.Fatalf("ParseBundle() error = %v", err)
	}
	if identity.Kind() != KindBundle {
		t.Fatalf("Kind() = %v, want KindBundle", identity.Kind())
	}
	if identity.Path() != "dependency-policy/v1" {
		t.Fatalf("Path() = %q", identity.Path())
	}
	if identity.Digest() != testDigestForm {
		t.Fatalf("Digest() = %q", identity.Digest())
	}
	if identity.String() != "dependency-policy/v1@"+testDigestForm {
		t.Fatalf("String() = %q", identity.String())
	}
	if !identity.Valid() {
		t.Fatal("Valid() = false, want true")
	}
}

func TestParseBundleRejectsDeviations(t *testing.T) {
	for name, value := range map[string]string{
		"other schema version": "dependency-policy/v2@" + testDigestForm,
		"other path":           "other/v1@" + testDigestForm,
		"nested path":          "dependency-policy/v1/extra@" + testDigestForm,
		"missing separator":    "dependency-policy/v1",
		"bad digest":           "dependency-policy/v1@sha256:12",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBundle(value); err == nil {
				t.Fatalf("ParseBundle(%q) error = nil, want rejection", value)
			}
		})
	}
}

func TestZeroIdentityIsNotValid(t *testing.T) {
	identity := Identity{}
	if identity.Valid() {
		t.Fatal("Valid() = true for the zero identity, want false")
	}
	if identity.Kind() != 0 || identity.Path() != "" || identity.Digest() != "" {
		t.Fatalf("zero identity = %v %q %q, want empty", identity.Kind(), identity.Path(), identity.Digest())
	}
	if identity.DigestHex() != "" {
		t.Fatalf("zero identity DigestHex() = %q, want empty", identity.DigestHex())
	}
	if identity.String() != "@" {
		t.Fatalf("zero identity String() = %q, want the bare separator", identity.String())
	}
}
