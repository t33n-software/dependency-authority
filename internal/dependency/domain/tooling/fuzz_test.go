package tooling

import (
	"strings"
	"testing"
)

// FuzzParse exercises the tooling channel identity parsers as a boundary: any
// input either fails closed or round-trips through the identity reference
// form.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256:" + strings.Repeat("a", 64),
		"osv-db/go@sha256:" + strings.Repeat("a", 64),
		"dependency-policy/v1@sha256:" + strings.Repeat("a", 64),
		"",
		"bogus",
		"osv-scanner/v2.5.1/osv-scanner_linux_amd64",
		"osv-db/go@sha256:zz",
		"\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, parse := range []func(string) (Identity, error){ParseTool, ParseDatabase, ParseBundle} {
			identity, err := parse(value)
			if err != nil {
				continue
			}
			if !identity.Valid() {
				t.Fatalf("Parse(%q) produced an invalid identity", value)
			}
			if identity.String() != value {
				t.Fatalf("Parse(%q) round-trip = %q, want the exact input", value, identity.String())
			}
		}
	})
}
