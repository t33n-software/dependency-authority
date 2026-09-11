package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/tooling"
)

var testToolingDigest = "sha256:" + strings.Repeat("a", 64)

var (
	testToolIdentity     = "osv-scanner/v2.5.1/osv-scanner_linux_amd64@" + testToolingDigest
	testDatabaseIdentity = "osv-db/go@" + testToolingDigest
	testBundleIdentity   = "dependency-policy/v1@" + testToolingDigest
)

// channelEnv carries the materializer transport bindings plus the given lane
// values.
func channelEnv(values map[string]string) map[string]string {
	base := map[string]string{
		config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
		config.EnvEvidenceRepository: "projects/p/locations/l/repositories/evidence",
	}
	for key, value := range values {
		base[key] = value
	}
	return base
}

// scannerChannelEnv carries the complete scanner contract with valid channel
// identities.
func scannerChannelEnv() map[string]string {
	return map[string]string{
		config.EnvScannerTool:             "tools/osv-scanner",
		config.EnvScannerDatabase:         "tools/osv-db",
		config.EnvScanContentRoot:         "work/content",
		config.EnvScannerIdentity:         testToolIdentity,
		config.EnvScannerDatabaseIdentity: testDatabaseIdentity,
	}
}

func TestToolingChannelRequestsScopesTheLanes(t *testing.T) {
	full := scannerChannelEnv()
	full[config.EnvPolicyBundle] = "policies/go.json"
	full[config.EnvPolicyBundleIdentity] = testBundleIdentity

	t.Run("intake carries no channel scope", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationIntake, mustBindings(t, channelEnv(full)), envBinding(channelEnv(full)))
		if err != nil || requests != nil {
			t.Fatalf("toolingChannelRequests(intake) = %v, %v, want no scope", requests, err)
		}
	})

	t.Run("revocation carries no channel scope", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationRevocation, mustBindings(t, channelEnv(full)), envBinding(channelEnv(full)))
		if err != nil || requests != nil {
			t.Fatalf("toolingChannelRequests(revocation) = %v, %v, want no scope", requests, err)
		}
	})

	t.Run("admission without channel bindings carries no scope", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(nil)), envBinding(channelEnv(nil)))
		if err != nil || requests != nil {
			t.Fatalf("toolingChannelRequests(admission) = %v, %v, want no scope", requests, err)
		}
	})

	t.Run("admission with a partial scanner contract carries no scanner scope", func(t *testing.T) {
		partial := map[string]string{config.EnvScannerTool: "tools/osv-scanner"}
		requests, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(partial)), envBinding(channelEnv(partial)))
		if err != nil || requests != nil {
			t.Fatalf("toolingChannelRequests(admission, partial) = %v, %v, want no scope", requests, err)
		}
	})

	t.Run("admission with the scanner contract materializes tool and database", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(scannerChannelEnv())), envBinding(channelEnv(scannerChannelEnv())))
		if err != nil {
			t.Fatalf("toolingChannelRequests() error = %v", err)
		}
		if len(requests) != 2 {
			t.Fatalf("toolingChannelRequests() = %d requests, want 2", len(requests))
		}
		if requests[0].Identity().String() != testToolIdentity || requests[0].Target() != "tools/osv-scanner" || requests[0].Mode() != 0o755 {
			t.Fatalf("tool request = %q %q %o", requests[0].Identity(), requests[0].Target(), requests[0].Mode())
		}
		wantDatabaseTarget := filepath.Join("tools", "osv-db", "osv-scalibr", "Go", "all.zip")
		if requests[1].Identity().String() != testDatabaseIdentity || requests[1].Target() != wantDatabaseTarget || requests[1].Mode() != 0o644 {
			t.Fatalf("database request = %q %q %o", requests[1].Identity(), requests[1].Target(), requests[1].Mode())
		}
	})

	t.Run("admission with the full scope materializes tool, database, and bundle", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(full)), envBinding(channelEnv(full)))
		if err != nil {
			t.Fatalf("toolingChannelRequests() error = %v", err)
		}
		if len(requests) != 3 {
			t.Fatalf("toolingChannelRequests() = %d requests, want 3", len(requests))
		}
		if requests[2].Identity().String() != testBundleIdentity || requests[2].Target() != "policies/go.json" || requests[2].Mode() != 0o644 {
			t.Fatalf("bundle request = %q %q %o", requests[2].Identity(), requests[2].Target(), requests[2].Mode())
		}
	})

	t.Run("revalidation shares the admission scope", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationRevalidation, mustBindings(t, channelEnv(full)), envBinding(channelEnv(full)))
		if err != nil || len(requests) != 3 {
			t.Fatalf("toolingChannelRequests(revalidation) = %v, %v, want 3 requests", requests, err)
		}
	})

	t.Run("promotion materializes the bundle only", func(t *testing.T) {
		bundle := map[string]string{
			config.EnvPolicyBundle:         "policies/go.json",
			config.EnvPolicyBundleIdentity: testBundleIdentity,
		}
		requests, err := toolingChannelRequests(OperationPromotion, mustBindings(t, channelEnv(bundle)), envBinding(channelEnv(bundle)))
		if err != nil || len(requests) != 1 {
			t.Fatalf("toolingChannelRequests(promotion) = %v, %v, want the bundle request", requests, err)
		}
	})

	t.Run("promotion without the bundle path carries no scope", func(t *testing.T) {
		requests, err := toolingChannelRequests(OperationPromotion, mustBindings(t, channelEnv(nil)), envBinding(channelEnv(nil)))
		if err != nil || requests != nil {
			t.Fatalf("toolingChannelRequests(promotion) = %v, %v, want no scope", requests, err)
		}
	})
}

func TestToolingChannelRequestsFailsClosedOnTheIdentities(t *testing.T) {
	t.Run("malformed tool identity", func(t *testing.T) {
		values := scannerChannelEnv()
		values[config.EnvScannerIdentity] = "osv-scanner 2.2.3"
		_, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(values)), envBinding(channelEnv(values)))
		if err == nil || !strings.Contains(err.Error(), config.EnvScannerIdentity) {
			t.Fatalf("toolingChannelRequests() error = %v, want the tool identity failure", err)
		}
	})

	t.Run("malformed database identity", func(t *testing.T) {
		values := scannerChannelEnv()
		values[config.EnvScannerDatabaseIdentity] = "osv-db sha256:aaa"
		_, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(values)), envBinding(channelEnv(values)))
		if err == nil || !strings.Contains(err.Error(), config.EnvScannerDatabaseIdentity) {
			t.Fatalf("toolingChannelRequests() error = %v, want the database identity failure", err)
		}
	})

	t.Run("missing bundle identity", func(t *testing.T) {
		values := map[string]string{config.EnvPolicyBundle: "policies/go.json"}
		_, err := toolingChannelRequests(OperationAdmission, mustBindings(t, channelEnv(values)), envBinding(channelEnv(values)))
		if err == nil || !strings.Contains(err.Error(), config.EnvPolicyBundleIdentity) {
			t.Fatalf("toolingChannelRequests() error = %v, want the bundle identity failure", err)
		}
	})

	t.Run("malformed bundle identity on promotion", func(t *testing.T) {
		values := map[string]string{
			config.EnvPolicyBundle:         "policies/go.json",
			config.EnvPolicyBundleIdentity: "dependency-policy/v2@" + testToolingDigest,
		}
		_, err := toolingChannelRequests(OperationPromotion, mustBindings(t, channelEnv(values)), envBinding(channelEnv(values)))
		if err == nil || !strings.Contains(err.Error(), config.EnvPolicyBundleIdentity) {
			t.Fatalf("toolingChannelRequests() error = %v, want the bundle identity failure", err)
		}
	})
}

// mustBindings loads the bindings from the given environment map.
func mustBindings(t *testing.T, values map[string]string) config.Bindings {
	t.Helper()
	bindings, err := config.BindingsFromEnv(envBinding(values))
	if err != nil {
		t.Fatalf("BindingsFromEnv() error = %v", err)
	}
	return bindings
}

// fakeChannelMaterializer records the materialization calls.
type fakeChannelMaterializer struct {
	err      error
	calls    int
	requests []tooling.Request
}

func (f *fakeChannelMaterializer) Materialize(_ context.Context, requests ...tooling.Request) error {
	f.calls++
	f.requests = append(f.requests, requests...)
	return f.err
}

// stubChannelMaterializerFactory binds the materializer factory seam to the
// fake.
func stubChannelMaterializerFactory(t *testing.T, materializer *fakeChannelMaterializer, err error) {
	t.Helper()
	original := newChannelMaterializer
	t.Cleanup(func() { newChannelMaterializer = original })
	newChannelMaterializer = func(string, string) (channelMaterializer, error) {
		if err != nil {
			return nil, err
		}
		return materializer, nil
	}
}

func TestMaterializeToolingChannelRejectsANilLookup(t *testing.T) {
	if err := materializeToolingChannel(context.Background(), OperationAdmission, nil); err == nil {
		t.Fatal("materializeToolingChannel( nil lookup ) error = nil, want error")
	}
}

func TestMaterializeToolingChannelPropagatesTheRequestBuildFailure(t *testing.T) {
	values := scannerChannelEnv()
	values[config.EnvScannerIdentity] = "bogus"
	if err := materializeToolingChannel(context.Background(), OperationAdmission, envBinding(channelEnv(values))); err == nil || !strings.Contains(err.Error(), config.EnvScannerIdentity) {
		t.Fatalf("materializeToolingChannel() error = %v, want the identity failure", err)
	}
}

func TestMaterializeToolingChannelWithoutScopeBindsNoMaterializer(t *testing.T) {
	called := false
	original := newChannelMaterializer
	t.Cleanup(func() { newChannelMaterializer = original })
	newChannelMaterializer = func(string, string) (channelMaterializer, error) {
		called = true
		return nil, errors.New("no call expected")
	}
	if err := materializeToolingChannel(context.Background(), OperationIntake, envBinding(channelEnv(nil))); err != nil {
		t.Fatalf("materializeToolingChannel() error = %v", err)
	}
	if called {
		t.Fatal("materializeToolingChannel() constructed the materializer without a channel scope")
	}
}

func TestMaterializeToolingChannelPropagatesTheFactoryFailure(t *testing.T) {
	stubChannelMaterializerFactory(t, &fakeChannelMaterializer{}, errors.New("no evidence repository"))
	if err := materializeToolingChannel(context.Background(), OperationPromotion, envBinding(channelEnv(map[string]string{
		config.EnvPolicyBundle:         "policies/go.json",
		config.EnvPolicyBundleIdentity: testBundleIdentity,
	}))); err == nil || !strings.Contains(err.Error(), "bind the tooling channel materializer") {
		t.Fatalf("materializeToolingChannel() error = %v, want the factory failure", err)
	}
}

func TestMaterializeToolingChannelPropagatesTheMaterializationFailure(t *testing.T) {
	stubChannelMaterializerFactory(t, &fakeChannelMaterializer{err: errors.New("digest drift")}, nil)
	if err := materializeToolingChannel(context.Background(), OperationPromotion, envBinding(channelEnv(map[string]string{
		config.EnvPolicyBundle:         "policies/go.json",
		config.EnvPolicyBundleIdentity: testBundleIdentity,
	}))); err == nil || !strings.Contains(err.Error(), "materialize the tooling channel") {
		t.Fatalf("materializeToolingChannel() error = %v, want the materialization failure", err)
	}
}

func TestMaterializeToolingChannelMaterializesTheFullScope(t *testing.T) {
	materializer := &fakeChannelMaterializer{}
	stubChannelMaterializerFactory(t, materializer, nil)
	full := scannerChannelEnv()
	full[config.EnvPolicyBundle] = "policies/go.json"
	full[config.EnvPolicyBundleIdentity] = testBundleIdentity
	if err := materializeToolingChannel(context.Background(), OperationAdmission, envBinding(channelEnv(full))); err != nil {
		t.Fatalf("materializeToolingChannel() error = %v", err)
	}
	if materializer.calls != 1 || len(materializer.requests) != 3 {
		t.Fatalf("materializer calls = %d with %d requests, want 1 call with 3 requests", materializer.calls, len(materializer.requests))
	}
	if materializer.requests[0].Identity().String() != testToolIdentity || materializer.requests[2].Identity().String() != testBundleIdentity {
		t.Fatalf("materializer requests = %q … %q", materializer.requests[0].Identity(), materializer.requests[2].Identity())
	}
}

func TestNewChannelMaterializerBindsTheProductionMaterializer(t *testing.T) {
	// The production seam is called directly (not swapped): the construction
	// validates the endpoint and repository and performs no network I/O.
	materializer, err := newChannelMaterializer("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/evidence")
	if err != nil {
		t.Fatalf("newChannelMaterializer() error = %v", err)
	}
	if materializer == nil {
		t.Fatal("newChannelMaterializer() = nil, want the production materializer")
	}
}
