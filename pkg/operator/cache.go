package operator

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const lastAppliedConfigurationAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// ClientCacheOptions returns the cache configuration for the manager's client,
// listing the object types whose reads bypass the shared informer cache and go
// straight to the API server.
//
// Secret and ServiceAccount are listed because their contents are never served
// from the cache. ConfigMap is listed because CacheTransform strips ConfigMap
// contents on the way in, so a cached read would return an object with no Data.
//
// Both Start and the envtest suite configure their manager from this function,
// so the tests exercise the production configuration instead of a copy that can
// drift. Each call returns independent values, including a new DisableFor slice,
// so one caller cannot mutate the configuration used by another.
func ClientCacheOptions() *client.CacheOptions {
	return &client.CacheOptions{
		DisableFor: []client.Object{
			&corev1.Secret{},
			&corev1.ServiceAccount{},
			&corev1.ConfigMap{},
		},
	}
}

// CacheTransform returns the transform applied to every object entering the
// operator's shared informer cache. It strips managed fields, the
// last-applied-configuration annotation and the Data and BinaryData of every
// ConfigMap, all of which keep the cache small.
//
// ConfigMap contents are stripped even though ConfigMap is in
// ClientCacheOptions' DisableFor list, because the two settings act on
// different paths. DisableFor only changes where reads through the manager
// client go; it does not stop the informers. Config-audit, ChecksLoader and
// PolicyConfigController all watch ConfigMaps, so without this transform the
// informer store would hold the contents of every watched ConfigMap in memory
// while nothing ever read them from there.
//
// Stripping is therefore safe: every ConfigMap read through the manager client
// - including the object config-audit serializes into Rego - is served by the
// API server and carries full contents.
func CacheTransform() toolscache.TransformFunc {
	stripManagedFields := cache.TransformStripManagedFields()

	return func(obj any) (any, error) {
		obj, err := stripManagedFields(obj)
		if err != nil {
			return obj, err
		}

		if metaObj, ok := obj.(metav1.ObjectMetaAccessor); ok {
			annotations := metaObj.GetObjectMeta().GetAnnotations()
			if annotations != nil {
				delete(annotations, lastAppliedConfigurationAnnotation)
				metaObj.GetObjectMeta().SetAnnotations(annotations)
			}
		}

		if cm, ok := obj.(*corev1.ConfigMap); ok {
			cm.Data = nil
			cm.BinaryData = nil
		}

		return obj, nil
	}
}
