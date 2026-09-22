package operator

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// TestClientCacheOptions pins the set of types whose reads bypass the informer
// cache. ConfigMap must stay in the list for as long as CacheTransform strips
// ConfigMap contents, or cached reads would hand back an object with no Data.
func TestClientCacheOptions(t *testing.T) {
	opts := ClientCacheOptions()
	require.NotNil(t, opts)

	got := make([]string, 0, len(opts.DisableFor))
	for _, obj := range opts.DisableFor {
		got = append(got, fmt.Sprintf("%T", obj))
	}
	assert.ElementsMatch(t, []string{"*v1.Secret", "*v1.ServiceAccount", "*v1.ConfigMap"}, got)
}

// TestClientCacheOptions_ReturnsFreshValue guards against the options - or the
// slice inside them - being shared between the operator and the envtest suite,
// where one caller mutating them would silently reconfigure the other.
func TestClientCacheOptions_ReturnsFreshValue(t *testing.T) {
	first := ClientCacheOptions()
	second := ClientCacheOptions()

	assert.NotSame(t, first, second)

	first.DisableFor = first.DisableFor[:0]
	first.DisableFor = append(first.DisableFor, &corev1.Pod{})

	assert.Len(t, second.DisableFor, 3, "mutating one result must not affect another")
	for _, obj := range second.DisableFor {
		assert.NotEqual(t, "*v1.Pod", fmt.Sprintf("%T", obj),
			"mutation leaked into a later call")
	}
}

func configMapWithSecretData(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Data: map[string]string{
			"password":               "SuperSecret123",
			"application.properties": "username=admin\npassword=SuperSecret123\nnormal_setting=true\n",
		},
		BinaryData: map[string][]byte{
			"keystore.jks": []byte("binary-secret"),
		},
	}
}

// TestCacheTransform_StripsConfigMapData guards the memory optimization: no
// ConfigMap contents are ever held in the shared informer cache, not even those
// of the operator's own ConfigMaps. ConfigMap is listed in the manager's
// client.CacheOptions.DisableFor, so every read returns a full object from the
// API server anyway - see the envtest regression spec in tests/envtest.
func TestCacheTransform_StripsConfigMapData(t *testing.T) {
	tests := []struct {
		name      string
		configMap string
	}{
		{"ordinary ConfigMap", "kap-configmap-secret-test"},
		{"policies ConfigMap", trivyoperator.PoliciesConfigMapName},
		{"trivy config ConfigMap", trivyoperator.TrivyConfigMapName},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CacheTransform()(configMapWithSecretData(tc.configMap))
			require.NoError(t, err)

			got, ok := out.(*corev1.ConfigMap)
			require.True(t, ok)

			assert.Nil(t, got.Data)
			assert.Nil(t, got.BinaryData)

			// Identity is never stripped; the config-audit report is keyed on it.
			assert.Equal(t, tc.configMap, got.Name)
			assert.Equal(t, "default", got.Namespace)
		})
	}
}

func TestCacheTransform_StripsManagedFieldsAndLastAppliedConfiguration(t *testing.T) {
	cm := configMapWithSecretData(trivyoperator.TrivyConfigMapName)
	cm.ManagedFields = []metav1.ManagedFieldsEntry{
		{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply},
	}
	cm.Annotations = map[string]string{
		lastAppliedConfigurationAnnotation: "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\"}",
		"keep-me":                          "yes",
	}

	out, err := CacheTransform()(cm)
	require.NoError(t, err)

	got := out.(*corev1.ConfigMap)
	assert.Empty(t, got.ManagedFields)
	assert.NotContains(t, got.Annotations, lastAppliedConfigurationAnnotation)
	assert.Equal(t, "yes", got.Annotations["keep-me"])
}

func TestCacheTransform_LeavesOtherKindsAlone(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "default"},
		Data:       map[string][]byte{"password": []byte("SuperSecret123")},
	}

	out, err := CacheTransform()(secret)
	require.NoError(t, err)
	assert.Equal(t, []byte("SuperSecret123"), out.(*corev1.Secret).Data["password"],
		"ConfigMap stripping must not leak into other types")
}

// TestCacheTransform_ThroughSharedInformer drives the transform through a real
// client-go shared informer - the machinery controller-runtime's cache is built
// on - so that the cached representation, not just the function, is asserted.
func TestCacheTransform_ThroughSharedInformer(t *testing.T) {
	const name = "kap-configmap-secret-test"

	clientset := fake.NewClientset(configMapWithSecretData(name))

	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0,
		informers.WithNamespace("default"),
		informers.WithTransform(CacheTransform()),
	)
	informer := factory.Core().V1().ConfigMaps().Informer()

	stop := make(chan struct{})
	defer close(stop)
	factory.Start(stop)

	require.Eventually(t, informer.HasSynced, 10*time.Second, 10*time.Millisecond,
		"informer did not sync")

	obj, exists, err := informer.GetStore().GetByKey("default/" + name)
	require.NoError(t, err)
	require.True(t, exists, "ConfigMap not found in informer store")

	cached := obj.(*corev1.ConfigMap)
	assert.Nil(t, cached.Data)
	assert.Nil(t, cached.BinaryData)
}
