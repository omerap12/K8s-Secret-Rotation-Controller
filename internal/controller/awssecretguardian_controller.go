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
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/sts"
	corev1 "k8s.io/api/core/v1"

	secretguardianv1alpha1 "github.com/omerap12/K8s-Secret-Rotation-Controller/api/v1alpha1"
)

// AWSSecretGuardianReconciler reconciles a AWSSecretGuardian object
type AWSSecretGuardianReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *AWSSecretGuardianReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { //
	access_key, secret_key, err := r.GetCreds(ctx, "awssecretguardian", "aws-creds")
	if err != nil {
		fmt.Println("Error: ", err)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if access_key == "" || secret_key == "" {
		fmt.Println("Error retieiving access-key and secret-access-key (value may be null)")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	userARN, err := r.GetUserARN("us-east-1", access_key, secret_key)
	if err != nil {
		fmt.Println(err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	fmt.Println(userARN)

	awsSecretGuardiansList := &secretguardianv1alpha1.AWSSecretGuardianList{} // create the list object of all the AWSSecretGuardian objects
	err = r.List(ctx, awsSecretGuardiansList)                                 // get the list of all the AWSSecretGuardian objects
	if err != nil {
		fmt.Println("error getting SecretGuardian Object")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	for _, awsSecretGuardian := range awsSecretGuardiansList.Items {
		fmt.Println("Handling ", awsSecretGuardian.Name)
		region, secretName, _, level, _, _ := awsSecretGuardian.Spec.Region, awsSecretGuardian.Spec.Name, awsSecretGuardian.Spec.Length, awsSecretGuardian.Spec.Level, awsSecretGuardian.Spec.TTL, awsSecretGuardian.Spec.Namespace
		secretExist, err := r.CheckSecretExist(region, access_key, secret_key, secretName, 15, level)
		if err != nil {
			fmt.Println(err)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if secretExist {
			fmt.Printf("Secret %s exist\n", secretName)
		} else {
			fmt.Printf("Secret %s doen't exist. creating ..\n", secretName)
		}
		ok, err := r.SecretManagerHandler(region, access_key, secret_key, secretName, 1, level, secretExist)
		if err != nil {
			fmt.Println(err)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if ok {
			fmt.Println("SecretUpdated.")
		}
	}
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSSecretGuardianReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretguardianv1alpha1.AWSSecretGuardian{}).
		Complete(r)
}

func (r *AWSSecretGuardianReconciler) GetCreds(ctx context.Context, nameSpaceName string, secretName string) (string, string, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: nameSpaceName}, secret)
	if err != nil {
		return "", "", err
	}
	access_key := string(secret.Data["access-key"])
	secret_key := string(secret.Data["secret-access-key"])
	return access_key, secret_key, nil
}

func (r *AWSSecretGuardianReconciler) GetUserARN(region string, access_key string, secret_access_key string) (string, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	// Create a new AWS STS client
	svc := sts.New(sess)
	result, err := svc.GetCallerIdentity(nil)
	if err != nil {
		return "", err
	}
	return *result.Arn, nil
}

func (r *AWSSecretGuardianReconciler) CheckSecretExist(region string, access_key string, secret_access_key string, secretName string, length int, level string) (bool, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))

	svc := secretsmanager.New(sess)
	input := &secretsmanager.ListSecretsInput{}
	result, err := svc.ListSecrets(input)
	if err != nil {
		return false, err
	}
	secretsList := result.SecretList
	for _, value := range secretsList {
		if secretName == *value.Name {
			return true, nil
		}
	}
	return false, nil
}

func (r *AWSSecretGuardianReconciler) SecretManagerHandler(region string, access_key string, secret_access_key string, secretName string, length int, level string, secretExist bool) (bool, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	svc := secretsmanager.New(sess)
	if secretExist {
		input := &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(secretName),
			Description:  aws.String("Secret Managed By AWSGuardian"),
			SecretString: aws.String("blabla"),
		}
		_, err := svc.UpdateSecret(input)
		if err != nil {
			return false, err
		}
	} else {
		input := &secretsmanager.CreateSecretInput{
			Description:  aws.String("Secret Managed By AWSGuardian"),
			Name:         aws.String(secretName),
			SecretString: aws.String("blabla"),
		}
		_, err := svc.CreateSecret(input)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}
