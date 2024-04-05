/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AWSSecretGuardianSpec defines the desired state of AWSSecretGuardian
type AWSSecretGuardianSpec struct {
	Region    string `json:"region"`
	Name      string `json:"name"`
	Length    int    `json:"length"`
	Level     string `json:"level"`
	TTL       int    `json:"ttl"`
	Namespace string `json:"namespace"`
}

// AWSSecretGuardianStatus defines the observed state of AWSSecretGuardian
type AWSSecretGuardianStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AWSSecretGuardian is the Schema for the awssecretguardians API
type AWSSecretGuardian struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AWSSecretGuardianSpec   `json:"spec,omitempty"`
	Status AWSSecretGuardianStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AWSSecretGuardianList contains a list of AWSSecretGuardian
type AWSSecretGuardianList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSSecretGuardian `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AWSSecretGuardian{}, &AWSSecretGuardianList{})
}
