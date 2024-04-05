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

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"time"

	corev1 "k8s.io/api/core/v1"

	secretguardianv1alpha1 "github.com/omerap12/K8s-Secret-Rotation-Controller/api/v1alpha1"
)

// AWSSecretGuardianReconciler reconciles a AWSSecretGuardian object
type AWSSecretGuardianReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=secretguardian.omerap12.com,resources=awssecretguardians,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secretguardian.omerap12.com,resources=awssecretguardians/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secretguardian.omerap12.com,resources=awssecretguardians/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AWSSecretGuardian object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *AWSSecretGuardianReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// jsonHandler := slog.NewJSONHandler(os.Stderr, nil)
	// operatorLogger := slog.New(jsonHandler)
	// secretGuardian := &secretguardianv1alpha1.AWSSecretGuardian{}
	//
	access_key, secret_key, err := r.getCreds(ctx, "awssecretguardian", "aws-creds")
	if err != nil {
		fmt.Println("Error: ", err)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if access_key == "" || secret_key == "" {
		fmt.Println("Error retieiving access-key and secret-access-key")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	awsSecretGuardiansList := &secretguardianv1alpha1.AWSSecretGuardianList{} // create the list object of all the AWSSecretGuardian objects
	err = r.List(ctx, awsSecretGuardiansList)                                 // get the list of all the AWSSecretGuardian objects
	if err != nil {
		fmt.Println("error getting DeathTimer object")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	for _, awsSecretGuardian := range awsSecretGuardiansList.Items {
		fmt.Println("Handling ", awsSecretGuardian.Name)
	}

	return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSSecretGuardianReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretguardianv1alpha1.AWSSecretGuardian{}).
		Complete(r)
}

// func (r *AWSSecretGuardianReconciler) authenticateAWS (ctx context.Context) (bool, error) {
// 	// load the the aws access and secret key.

// }

func (r *AWSSecretGuardianReconciler) getCreds(ctx context.Context, nameSpaceName string, secretName string) (string, string, error) {
	// secret := &corev1.Secret{}
	// nameSpaceObj := &corev1.Namespace{}
	// err := r.Get(ctx, client.ObjectKey {Name: nameSpaceName}, nameSpaceObj) // get the desire namespace object into nameSpaceObj variable
	// if err != nil {
	// 	return false, err
	// }

	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: nameSpaceName}, secret)
	if err != nil {
		return "", "", err
	}
	access_key := string(secret.Data["access-key"])
	secret_key := string(secret.Data["secret-access-key"])
	return access_key, secret_key, nil
}


