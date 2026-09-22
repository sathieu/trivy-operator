package operator_test

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

const (
	// fixtureLibraryKey is the policies ConfigMap key holding the fixture's own
	// copy of the kubernetes helper library.
	fixtureLibraryKey = "library.fixture.rego"
	// hostIPCCheckID is the check declared by the fixture's policy.
	hostIPCCheckID = "KSV008"
	// configMapCheckID is the local, envtest-only ConfigMap check.
	configMapCheckID = "ENVTEST001"
)

// fixtureAuditConfig is a configauditreport.ConfigAuditConfig whose only
// interesting knob is whether the built-in Rego policies are loaded.
type fixtureAuditConfig struct {
	builtin bool
}

func (c fixtureAuditConfig) GetUseBuiltinRegoPolicies() bool  { return c.builtin }
func (c fixtureAuditConfig) GetUseEmbeddedRegoPolicies() bool { return false }
func (c fixtureAuditConfig) GetSeverity() string              { return "" }
func (c fixtureAuditConfig) GetSupportedConfigAuditKinds() []string {
	return []string{"Workload", "ConfigMap"}
}

// loadPolicyFixture returns the data of the policies ConfigMap fixture that
// controller_test.go applies to the cluster.
func loadPolicyFixture(t *testing.T) map[string]string {
	t.Helper()

	cm := &corev1.ConfigMap{}
	if err := loadResource(cm, filepath.Join("testdata", "fixture", "policy.yaml")); err != nil {
		t.Fatalf("loading policy fixture: %v", err)
	}
	if len(cm.Data) == 0 {
		t.Fatal("policy fixture carries no data")
	}
	return cm.Data
}

// readContentModule reads one rego module out of testdata/content. Modules are
// read by path so that these tests assert on the module contents alone; the
// envtest specs cover the real policy loader.
func readContentModule(t *testing.T, parts ...string) string {
	t.Helper()

	full := filepath.Join(append([]string{"testdata", "content", "policies", "kubernetes"}, parts...)...)
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("reading %s: %v", full, err)
	}
	return string(raw)
}

// loadedPolicies builds a scanner over data and fails the test if it does not
// compile.
func loadedPolicies(t *testing.T, data map[string]string, builtin bool) *policy.Policies {
	t.Helper()

	ttl := time.Hour
	policies := policy.NewPolicies(data, fixtureAuditConfig{builtin: builtin},
		ctrl.Log.WithName("policy-fixture-test"), &TestLoader{}, "1.27.1", &ttl)
	if err := policies.Load(); err != nil {
		t.Fatalf("loading policies: %v", err)
	}
	return policies
}

// failedCheckIDs returns the ids of the checks that failed for resource.
func failedCheckIDs(policies *policy.Policies, resource client.Object) (map[string]bool, error) {
	results, err := policies.Eval(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(results))
	for _, result := range results {
		if result.Status() == scan.StatusFailed {
			ids[policy.GetResultID(result)] = true
		}
	}
	return ids, nil
}

func hostIPCPod() *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "host-ipc", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostIPC:    true,
			Containers: []corev1.Container{{Name: "nginx", Image: "nginx:1.16"}},
		},
	}
}

// TestPolicyFixtureIsSelfContained checks that the policies ConfigMap fixture
// evaluates on its own, with the built-in policies switched off.
//
// Its policy.1_host_ipc.rego imports a kubernetes helper library. The fixture
// carries that library itself, as package lib.fixture, so it does not depend on
// testdata/content being loaded.
//
// The subtests are a matched pair: deleting the library again must break the
// fixture, or the first subtest would pass even if the import resolved
// elsewhere.
func TestPolicyFixtureIsSelfContained(t *testing.T) {
	t.Run("evaluates with built-in policies disabled", func(t *testing.T) {
		failed, err := failedCheckIDs(loadedPolicies(t, loadPolicyFixture(t), false), hostIPCPod())
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if !failed[hostIPCCheckID] {
			t.Errorf("%s missing; got %v", hostIPCCheckID, failed)
		}
	})

	t.Run("the private library is load-bearing", func(t *testing.T) {
		data := maps.Clone(loadPolicyFixture(t))
		delete(data, fixtureLibraryKey)

		failed, err := failedCheckIDs(loadedPolicies(t, data, false), hostIPCPod())
		if err == nil && failed[hostIPCCheckID] {
			t.Errorf("%s still reported without %s; this test proves nothing",
				hostIPCCheckID, fixtureLibraryKey)
		}
	})
}

// TestPolicyFixtureCoexistsWithContentLibrary is the reason the fixture's
// library is package lib.fixture and not package lib.kubernetes.
//
// testdata/content already defines lib.kubernetes, and two modules in one
// package both declaring "default is_gatekeeper" is an OPA compile error. A
// fixture that re-declared lib.kubernetes would break the shared scanner for
// every spec in the suite once controller_test.go applied it to the cluster.
func TestPolicyFixtureCoexistsWithContentLibrary(t *testing.T) {
	data := maps.Clone(loadPolicyFixture(t))
	data["library.content_kubernetes.rego"] = readContentModule(t, "lib", "kubernetes.rego")

	failed, err := failedCheckIDs(loadedPolicies(t, data, false), hostIPCPod())
	if err != nil {
		t.Fatalf("fixture library and lib.kubernetes do not compile together: %v", err)
	}
	if !failed[hostIPCCheckID] {
		t.Errorf("%s missing when lib.kubernetes is loaded too; got %v", hostIPCCheckID, failed)
	}
}

// TestEnvtestConfigMapCheckHasLocalIdentity keeps the fixture check from
// drifting back to the upstream KSV109 identity it used to borrow, which made it
// look like coverage of the real no-secrets-in-configmap check.
func TestEnvtestConfigMapCheckHasLocalIdentity(t *testing.T) {
	module := readContentModule(t, "policies", "general", "configmap_with_secrets.rego")

	for _, upstream := range []string{"KSV109", "AVD-KSV-0109", "builtin.kubernetes"} {
		if strings.Contains(module, upstream) {
			t.Errorf("fixture check still carries the upstream identity %q", upstream)
		}
	}
	if !strings.Contains(module, "id: "+configMapCheckID) {
		t.Errorf("fixture check does not declare the local id %s", configMapCheckID)
	}
}

// TestEnvtestConfigMapCheckSeesConfigMapData is the unit-level half of
// configmap_configaudit_test.go: it proves the local check fires on ConfigMap
// Data, so that when the envtest spec sees the check pass the cause is the cache
// stripping the data rather than the check itself being broken.
func TestEnvtestConfigMapCheckSeesConfigMapData(t *testing.T) {
	policies := loadedPolicies(t, map[string]string{
		"library.content_kubernetes.rego": readContentModule(t, "lib", "kubernetes.rego"),
		"policy.configmap_secrets.rego":   readContentModule(t, "policies", "general", "configmap_with_secrets.rego"),
		"policy.configmap_secrets.kinds":  "ConfigMap",
	}, false)

	tests := []struct {
		name     string
		data     map[string]string
		wantFail bool
	}{
		{
			name:     "data stores a secret",
			data:     map[string]string{"password": "SuperSecret123"},
			wantFail: true,
		},
		{
			name:     "innocuous data",
			data:     map[string]string{"normal_setting": "true"},
			wantFail: false,
		},
		{
			name:     "no data, i.e. what a stripped cache hands over",
			data:     nil,
			wantFail: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
				ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"},
				Data:       tc.data,
			}

			failed, err := failedCheckIDs(policies, cm)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if failed[configMapCheckID] != tc.wantFail {
				t.Errorf("%s failed=%v, want %v", configMapCheckID, failed[configMapCheckID], tc.wantFail)
			}
		})
	}
}
