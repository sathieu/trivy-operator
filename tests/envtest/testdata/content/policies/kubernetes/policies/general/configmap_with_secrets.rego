# METADATA
# title: "[envtest fixture] ConfigMap stores a secret"
# description: "Test-only check. Fails when a ConfigMap's data looks like it stores a secret. It exists to prove that ConfigMap Data survives the informer cache transform and reaches Rego evaluation; it is not the upstream no-secrets-in-configmap check and must not be treated as one."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: ENVTEST001
#   avd_id: AVD-ENVTEST-0001
#   severity: HIGH
#   short_code: envtest-configmap-stores-secret
#   recommended_action: "Nothing - this check exists only to exercise ConfigMap data in the envtest suite."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: configmap
package trivyoperator.kubernetes.ENVTEST001

import data.lib.kubernetes

# configMapSecretKeys returns ConfigMap data keys whose value looks like a
# secret assignment, e.g. "password=SuperSecret123".
configMapSecretKeys[key] {
	kubernetes.kind == "ConfigMap"
	value := kubernetes.object.data[key]
	is_string(value)
	regex.match("(?i)(password|passwd|secret|token)\\s*(=|:)", value)
}

# configMapSecretKeys also returns ConfigMap data keys that are themselves named
# after a secret, e.g. "password: SuperSecret123".
configMapSecretKeys[key] {
	kubernetes.kind == "ConfigMap"
	kubernetes.object.data[key]
	regex.match("(?i)^(password|passwd|secret|token)$", key)
}

deny[res] {
	count(configMapSecretKeys) > 0

	msg := kubernetes.format(sprintf("%s '%s' in '%s' namespace stores secrets in key(s) %v", [kubernetes.kind, kubernetes.name, kubernetes.namespace, configMapSecretKeys]))

	res := {"msg": msg}
}
