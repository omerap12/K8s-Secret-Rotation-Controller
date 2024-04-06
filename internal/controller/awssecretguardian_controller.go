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

	"math/rand"
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

// +kubebuilder:rbac:groups=secretguardian.k8s.io,resources=awssecretguardians,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secretguardian.k8s.io,resources=awssecretguardians/status,verbs=get;update;patch
func (r *AWSSecretGuardianReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { //
	access_key, secret_key, err := r.GetCreds(ctx, "awssecretguardian", "aws-creds")
	if err != nil {
		fmt.Println("Error: ", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if access_key == "" || secret_key == "" {
		fmt.Println("Error retieiving access-key and secret-access-key (value may be null)")
		return ctrl.Result{RequeueAfter: 120 * time.Second}, nil
	}

	userARN, err := r.GetUserARN("us-east-1", access_key, secret_key)
	if err != nil {
		fmt.Println(err)
		return ctrl.Result{RequeueAfter: 120 * time.Second}, nil
	}
	fmt.Println(userARN)
	awsSecretGuardiansList := &secretguardianv1alpha1.AWSSecretGuardianList{} // create the list object of all the AWSSecretGuardian objects
	err = r.List(ctx, awsSecretGuardiansList)                                 // get the list of all the AWSSecretGuardian objects
	if err != nil {
		fmt.Println("error getting SecretGuardian Object")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	for _, awsSecretGuardian := range awsSecretGuardiansList.Items {
		region, secretName, length, level, _, _ := awsSecretGuardian.Spec.Region, awsSecretGuardian.Spec.Name, awsSecretGuardian.Spec.Length, awsSecretGuardian.Spec.Level, awsSecretGuardian.Spec.TTL, awsSecretGuardian.Spec.Namespace
		secretExist, err := r.CheckSecretExist(region, access_key, secret_key, secretName, 15, level)
		if err != nil {
			fmt.Println(err)
			return ctrl.Result{RequeueAfter: 120 * time.Second}, nil
		}
		ok, err := r.SecretManagerHandler(region, access_key, secret_key, secretName, length, level, secretExist)
		if err != nil {
			fmt.Println(err)
			return ctrl.Result{RequeueAfter: 120 * time.Second}, nil
		}
		if ok {
			fmt.Printf("Updated secret %s\n", secretName)
		}
	}
	return ctrl.Result{RequeueAfter: 300 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSSecretGuardianReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretguardianv1alpha1.AWSSecretGuardian{}).
		Complete(r)
}

// function to get the access key and secret key from the secret
// return the access key and secret key as strings
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

// function to get the ARN of the user using the AWS STS service
// return the ARN of the user as a string
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

// function to check if the secret already exists in the AWS Secret Manager
// return true if the secret exists, false if the secret does not exist
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

// function to create or update the secret in the AWS Secret Manager
// if the secret already exists, it will update the secret with a new password
// if the secret does not exist, it will create a new secret with a new password
// return true if the secret is created or updated successfully
func (r *AWSSecretGuardianReconciler) SecretManagerHandler(region string, access_key string, secret_access_key string, secretName string, length int, level string, secretExist bool) (bool, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	svc := secretsmanager.New(sess)
	password := r.GeneratePassword(length)
	fmt.Println(password)
	if secretExist {
		input := &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(secretName),
			Description:  aws.String("Secret Managed By AWSGuardian"),
			SecretString: aws.String(password),
		}
		_, err := svc.UpdateSecret(input)
		if err != nil {
			return false, err
		}
	} else {
		input := &secretsmanager.CreateSecretInput{
			Description:  aws.String("Secret Managed By AWSGuardian"),
			Name:         aws.String(secretName),
			SecretString: aws.String(password),
		}
		_, err := svc.CreateSecret(input)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// Function used to generate a random password of length n
// The password will be a mix of uppercase, lowercase, numbers and special characters
// return the generated password as a string
func (r *AWSSecretGuardianReconciler) GeneratePassword(length int) string {
	fmt.Println(length)
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?~"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	pass := string(password)
	return pass
}
