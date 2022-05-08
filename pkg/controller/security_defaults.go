package controller

import (
	"errors"
	"fmt"
	"log"
	"math/rand"

	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	podResource = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
)

func random() int {
	max := 1000999999
	min := 1000000000
	return rand.Intn(max-min) + min
}

// ApplySecurityDefaults implements the logic of our example admission controller webhook. For every pod that is created
// (outside of Kubernetes namespaces), it first checks if `runAsNonRoot` is set. If it is not, it is set to a default
// value of `false`. Furthermore, if `runAsUser` is not set (and `runAsNonRoot` was not initially set), it defaults
// `runAsUser` to a value of 1234.
//
// To demonstrate how requests can be rejected, this webhook further validates that the `runAsNonRoot` setting does
// not conflict with the `runAsUser` setting - i.e., if the former is set to `true`, the latter must not be `0`.
// Note that we combine both the setting of defaults and the check for potential conflicts in one webhook; ideally,
// the latter would be performed in a validating webhook admission controller.
func ApplySecurityDefaults(req *v1.AdmissionRequest) ([]patchOperation, error) {
	// This handler should only get called on Pod objects as per the MutatingWebhookConfiguration in the YAML file.
	// However, if (for whatever reason) this gets invoked on an object of a different kind, issue a log message but
	// let the object request pass through otherwise.
	if req.Resource != podResource {
		log.Printf("expect resource to be %s", podResource)
		return nil, nil
	}

	// Parse the Pod object.
	raw := req.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		return nil, fmt.Errorf("could not deserialize pod object: %v", err)
	}

	// Retrieve the `runAsNonRoot` and `runAsUser` values.
	var runAsNonRoot *bool
	var runAsUser *int64
	if pod.Spec.SecurityContext != nil {
		runAsNonRoot = pod.Spec.SecurityContext.RunAsNonRoot
		runAsUser = pod.Spec.SecurityContext.RunAsUser
	}

	// Create patch operations to apply sensible defaults, if those options are not set explicitly.
	var patches []patchOperation
	if runAsNonRoot == nil {
		patches = append(patches, patchOperation{
			Op:   "add",
			Path: "/spec/securityContext/runAsNonRoot",
			// The value must not be true if runAsUser is set to 0, as otherwise we would create a conflicting
			// configuration ourselves.
			Value: runAsUser == nil || *runAsUser != 0,
		})

		if runAsUser == nil {
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/spec/securityContext/runAsUser",
				Value: random(),
			})
		}
	} else if *runAsNonRoot == true && (runAsUser != nil && *runAsUser == 0) {
		// Make sure that the settings are not contradictory, and fail the object creation if they are.
		return nil, errors.New("runAsNonRoot specified, but runAsUser set to 0 (the root user)")
	}

	patches = append(patches, patchContainers("containers", pod.Spec.Containers)...)
	patches = append(patches, patchContainers("initContainers", pod.Spec.InitContainers)...)
	return patches, nil
}

func patchContainers(key string, containers []corev1.Container) []patchOperation {
	patches := []patchOperation{}
	for i, container := range containers {
		if container.SecurityContext == nil {
			allowPrivileged := false
			defaultContext := corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
				AllowPrivilegeEscalation: &allowPrivileged,
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			}

			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%d/securityContext", key, i),
				Value: defaultContext,
			})
		} else {
			if container.SecurityContext.AllowPrivilegeEscalation == nil {
				patches = append(patches, patchOperation{
					Op:    "add",
					Path:  fmt.Sprintf("/spec/%s/%d/securityContext/allowPrivilegeEscalation", key, i),
					Value: false,
				})
			}
			if container.SecurityContext.Capabilities == nil {
				patches = append(patches, patchOperation{
					Op:   "add",
					Path: fmt.Sprintf("/spec/%s/%d/securityContext/capabilities", key, i),
					Value: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				})
			}
			if container.SecurityContext.SeccompProfile == nil {
				patches = append(patches, patchOperation{
					Op:   "add",
					Path: fmt.Sprintf("/spec/%s/%d/securityContext/seccompProfile", key, i),
					Value: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				})
			}
		}
	}
	return patches
}
