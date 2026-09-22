package operator_test

import (
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Regression coverage for ConfigMap contents being stripped from the shared
// informer cache before config-audit evaluated them, which made every check
// that reads ConfigMap data pass vacuously.
//
// The whole production path is exercised here: the object goes through the real
// controller-runtime cache and client (both configured in suite_test.go from
// the operator's own operator.ClientCacheOptions and operator.CacheTransform),
// through the config-audit ResourceController, through policy.Policies.Eval and
// into Rego.
//
// The check driven here is the local fixture
// testdata/content/.../general/configmap_with_secrets.rego, whose id is
// deliberately ENVTEST001 in the trivyoperator namespace rather than any
// upstream KSV id: this spec proves that ConfigMap Data reaches Rego, and makes
// no claim about an upstream check's behaviour.
var _ = Describe("ConfigAudit on ConfigMap contents", func() {
	const (
		cmNamespace = "default"
		cmName      = "kap-configmap-secret-test"
		reportName  = "configmap-" + cmName
		// The local envtest-only check; see the fixture rego for why it is not a KSV id.
		checkID  = "ENVTEST001"
		timeout  = time.Second * 45
		interval = time.Millisecond * 250
	)

	findCheck := func(checks []v1alpha1.Check, id string) *v1alpha1.Check {
		for i := range checks {
			if checks[i].ID == id {
				return &checks[i]
			}
		}
		return nil
	}

	It("should report a failed check for a ConfigMap that stores a secret", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: cmNamespace,
			},
			Data: map[string]string{
				"password":               "SuperSecret123",
				"application.properties": "username=admin\npassword=SuperSecret123\nnormal_setting=true\n",
			},
		}
		Expect(k8sClient.Create(ctx, configMap)).Should(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, configMap)
		})

		key := client.ObjectKeyFromObject(configMap)

		By("confirming the API server holds the ConfigMap data")
		fromAPI := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, fromAPI)).Should(Succeed())
		Expect(fromAPI.Data).Should(HaveKeyWithValue("password", "SuperSecret123"))

		By("confirming the shared cache still strips the ConfigMap data")
		// This is the memory optimization the operator relies on, and the reason
		// ConfigMap is on the manager client's DisableFor list. If this assertion
		// ever fails the optimization has been dropped.
		cached := &corev1.ConfigMap{}
		Eventually(func(g Gomega) {
			g.Expect(cacheReader.Get(ctx, key, cached)).Should(Succeed())
			g.Expect(cached.Data).Should(BeNil())
		}, timeout, interval).Should(Succeed())

		By("confirming the client the controllers use still returns the data")
		// DisableFor sends ConfigMap reads to the API server, which is what makes
		// the stripped cache harmless.
		fromManager := &corev1.ConfigMap{}
		Expect(managerReader.Get(ctx, key, fromManager)).Should(Succeed())
		Expect(fromManager.Data).Should(HaveKeyWithValue("password", "SuperSecret123"))

		By("waiting for the ConfigAuditReport")
		report := &v1alpha1.ConfigAuditReport{}
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: cmNamespace, Name: reportName}, report)
		}, timeout, interval).Should(Succeed())

		By("asserting the ConfigMap data reached Rego")
		check := findCheck(report.Report.Checks, checkID)
		Expect(check).ShouldNot(BeNil(),
			"check %s missing from the report; config-audit did not evaluate the ConfigMap", checkID)
		Expect(check.Success).Should(BeFalse(),
			"check %s passed, which means Rego saw no ConfigMap data", checkID)
		Expect(strings.Join(check.Messages, " ")).Should(ContainSubstring("password"),
			"the finding must name the offending ConfigMap key")

		By("confirming the reconcile did not push the data into the shared cache")
		// The reconcile reads a full object from the API server; the informer
		// store must still hold a ConfigMap without contents, on this read and on
		// every later one, or the memory optimization has been defeated.
		for range 2 {
			afterReconcile := &corev1.ConfigMap{}
			Expect(cacheReader.Get(ctx, key, afterReconcile)).Should(Succeed())
			Expect(afterReconcile.Data).Should(BeNil(),
				"the reconcile leaked ConfigMap data into the informer cache")
			Expect(afterReconcile.BinaryData).Should(BeNil(),
				"the reconcile leaked ConfigMap binaryData into the informer cache")
		}

		By("confirming it still holds after a further update triggers another reconcile")
		updated := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, updated)).Should(Succeed())
		updated.Data["another.properties"] = "token=abc123"
		Expect(k8sClient.Update(ctx, updated)).Should(Succeed())

		Eventually(func(g Gomega) {
			// the API server keeps the new key ...
			fromAPIAgain := &corev1.ConfigMap{}
			g.Expect(k8sClient.Get(ctx, key, fromAPIAgain)).Should(Succeed())
			g.Expect(fromAPIAgain.Data).Should(HaveKey("another.properties"))

			// ... while the cache still holds nothing.
			afterUpdate := &corev1.ConfigMap{}
			g.Expect(cacheReader.Get(ctx, key, afterUpdate)).Should(Succeed())
			g.Expect(afterUpdate.Data).Should(BeNil())
			g.Expect(afterUpdate.BinaryData).Should(BeNil())
		}, timeout, interval).Should(Succeed())
	})

	It("should keep no ConfigMap contents in the cache, not even the operator's own", func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "configmap-cache-regression"},
		}
		Expect(k8sClient.Create(ctx, namespace)).Should(Succeed())

		names := []string{
			trivyoperator.PoliciesConfigMapName,
			trivyoperator.TrivyConfigMapName,
			"some-application-config",
		}

		for _, name := range names {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace.Name,
				},
				Data:       map[string]string{"password": "SuperSecret123"},
				BinaryData: map[string][]byte{"keystore.jks": []byte("binary-secret")},
			}
			Expect(k8sClient.Create(ctx, configMap)).Should(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, configMap)
			})

			key := client.ObjectKeyFromObject(configMap)

			cached := &corev1.ConfigMap{}
			Eventually(func(g Gomega) {
				g.Expect(cacheReader.Get(ctx, key, cached)).Should(Succeed())
				g.Expect(cached.Data).Should(BeNil())
				g.Expect(cached.BinaryData).Should(BeNil())
			}, timeout, interval).Should(Succeed(), "ConfigMap %s was cached with its contents", name)

			// Every read the operator itself makes still sees the contents.
			fromManager := &corev1.ConfigMap{}
			Expect(managerReader.Get(ctx, key, fromManager)).Should(Succeed())
			Expect(fromManager.Data).Should(HaveKeyWithValue("password", "SuperSecret123"), name)
			Expect(fromManager.BinaryData).Should(HaveKeyWithValue("keystore.jks", []byte("binary-secret")), name)
		}
	})
})
