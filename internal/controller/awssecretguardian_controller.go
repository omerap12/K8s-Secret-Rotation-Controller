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
	"encoding/json"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	log "sigs.k8s.io/controller-runtime/pkg/log"

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

var RequeueAfterTime time.Duration = 5
var RequeueAfterTimeKeys time.Duration = 10
var logger = log.Log.WithName("awssecretguardian-controller")

// +kubebuilder:rbac:groups=secretguardian.k8s.io,resources=awssecretguardians,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secretguardian.k8s.io,resources=awssecretguardians/status,verbs=get;update;patch
func (r *AWSSecretGuardianReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { //
	access_key, secret_key, err := r.GetCreds(ctx, "awssecretguardian", "aws-creds") // get the access key and secret key from the secret in the namespace awssecretguardian
	if err != nil {
		logger.Error(err, "Error getting access-key and secret-access-key from the secret in the namespace awssecretguardian (value may be null)")
		return ctrl.Result{RequeueAfter: RequeueAfterTimeKeys * time.Second}, nil
	}
	if access_key == "" || secret_key == "" {
		logger.Info("access-key or secret-access-key is empty")
		return ctrl.Result{RequeueAfter: RequeueAfterTime * time.Second}, nil
	}

	userARN, err := r.GetUserARN("us-east-1", access_key, secret_key) // get the ARN of the user using the AWS STS service
	if err != nil {
		logger.Info(fmt.Sprintf("Error getting user ARN: %s", err))
		return ctrl.Result{RequeueAfter: RequeueAfterTime * time.Second}, nil
	}
	logger.Info(fmt.Sprintf("User ARN: %s", userARN))
	awsSecretGuardiansList := &secretguardianv1alpha1.AWSSecretGuardianList{} // create the list object of all the AWSSecretGuardian objects
	err = r.List(ctx, awsSecretGuardiansList)                                 // get all the AWSSecretGuardian objects in the cluster
	if err != nil {
		logger.Info(fmt.Sprintf("Error getting the list of AWSSecretGuardian objects: %s", err))
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	for _, awsSecretGuardian := range awsSecretGuardiansList.Items { // iterate over all the AWSSecretGuardian objects
		region, secretName, length, ttl, keys, nameSpace := awsSecretGuardian.Spec.Region, awsSecretGuardian.Spec.Name, awsSecretGuardian.Spec.Length, awsSecretGuardian.Spec.TTL, awsSecretGuardian.Spec.Keys, awsSecretGuardian.ObjectMeta.Namespace // get the region, secret name, length, TTL, keys and namespace from the AWSSecretGuardian object
		secretExist, err := r.CheckAWSSecretExist(region, access_key, secret_key, secretName)                                                                                                                                                          // check if the secret already exists in the AWS Secret Manager
		if err != nil {
			logger.Info(fmt.Sprintf("Error checking if the secret exists in the AWS Secret Manager: %s", err))
			return ctrl.Result{RequeueAfter: RequeueAfterTime * time.Second}, nil
		}
		ok, err := r.SecretHandler(ctx, region, access_key, secret_key, nameSpace, ttl, secretName, keys, length, secretExist) // create or update the secret in the AWS Secret Manager
		if err != nil {
			logger.Info(fmt.Sprintf("Error creating or updating the secret in the AWS Secret Manager: %s", err))
			return ctrl.Result{RequeueAfter: RequeueAfterTime * time.Second}, nil
		}
		if ok {
			logger.Info(fmt.Sprintf("Secret %s created or updated in the AWS Secret Manager", secretName))
		} else {
			logger.Info(fmt.Sprintf("Secret %s TTL not reached", secretName))
		}
	}
	return ctrl.Result{RequeueAfter: RequeueAfterTime * time.Second}, nil
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
func (r *AWSSecretGuardianReconciler) CheckAWSSecretExist(region string, access_key string, secret_access_key string, secretName string) (bool, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{ // create a new session
		Region: aws.String(region),
	}))

	svc := secretsmanager.New(sess)             // create a new AWS Secret Manager client
	input := &secretsmanager.ListSecretsInput{} // create a new input object
	result, err := svc.ListSecrets(input)       // list all the secrets in the AWS Secret Manager
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
func (r *AWSSecretGuardianReconciler) SecretHandler(ctx context.Context, region string, access_key string, secret_access_key string, nameSpaceName string, ttl int, secretName string, keys []string, length int, secretExist bool) (bool, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", access_key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secret_access_key)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	svc := secretsmanager.New(sess)
	password, k8sSecretData, err := r.GeneratePassword(keys, length)
	if err != nil {
		return false, err
	}
	if secretExist {
		input := &secretsmanager.UpdateSecretInput{ // create a new input object
			SecretId:     aws.String(secretName),
			Description:  aws.String("Secret Managed By AWSGuardian"),
			SecretString: aws.String(password),
		}
		_, err := svc.UpdateSecret(input) // update the secret in the AWS Secret Manager
		if err != nil {
			return false, err
		}
	} else {
		input := &secretsmanager.CreateSecretInput{ // create a new input object
			Description:  aws.String("Secret Managed By AWSGuardian"),
			Name:         aws.String(secretName),
			SecretString: aws.String(password),
		}
		_, err := svc.CreateSecret(input) // create the secret in the AWS Secret Manager
		if err != nil {
			return false, err
		}
	}
	ok, err := r.K8SSecretHandler(ctx, nameSpaceName, ttl, secretName, k8sSecretData)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return true, nil
}

// Function used to generate a random password of length n
// The password will be a mix of uppercase, lowercase, numbers and special characters
// return the password as a string and the password as a map of keys and values as a byte array for the k8s secret
func (r *AWSSecretGuardianReconciler) GeneratePassword(keys []string, length int) (string, map[string][]byte, error) {
	k8sSecretData := make(map[string][]byte, len(keys))
	keyValueObject := make(map[string]string, len(keys))
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?~"
	for _, key := range keys {
		password := make([]byte, length)
		for i := range password {
			password[i] = charset[rand.Intn(len(charset))]
		}
		k8sSecretData[key] = password
		pass := string(password)
		keyValueObject[key] = pass
	}
	jsonString, err := json.Marshal(keyValueObject)
	if err != nil {
		return "", nil, err
	}
	return string(jsonString), k8sSecretData, nil
}

// function to create or update the secret in the k8s cluster
// if the secret already exists, it will update the secret with a new password
// if the secret does not exist, it will create a new secret with a new password
// return true if the secret is created or updated successfully
func (r *AWSSecretGuardianReconciler) K8SSecretHandler(ctx context.Context, nameSpaceName string, ttl int, secretName string, secretData map[string][]byte) (bool, error) {
	secretObj, err := r.GetSecretK8S(ctx, nameSpaceName, secretName) // get the secret object from the k8s cluster
	if err != nil {
		_, err := r.CreateUpdateK8SSecret(ctx, nameSpaceName, secretName, secretData, true) // create the secret in the k8s cluster
		if err != nil {
			return false, err
		}
	} else {
		annotationTime, err := time.Parse(time.RFC3339, secretObj.Annotations["K8s-Secret-Rotation-Controller"]) // get the annotation time from the secret object
		if err != nil {
			return false, err
		}
		if !time.Now().UTC().After(annotationTime.Add(time.Second * time.Duration(ttl))) { // check if the TTL of the secret has reached
			return false, nil
		}
		_, err = r.CreateUpdateK8SSecret(ctx, nameSpaceName, secretName, secretData, false) // update the secret in the k8s cluster
		if err != nil {
			return false, err
		}
	}
	logger.Info(fmt.Sprintf("Secret %s/%s created or updated", nameSpaceName, secretName))
	return true, nil
}

// function to get the secret object from the k8s cluster
// return the secret object
func (r *AWSSecretGuardianReconciler) GetSecretK8S(ctx context.Context, nameSpaceName string, secretName string) (*corev1.Secret, error) {
	secretObj := &corev1.Secret{}                                                              // create a new secret object
	err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: nameSpaceName}, secretObj) // get the secret object from the k8s cluster
	if err != nil {
		return nil, err
	}
	return secretObj, nil // return the secret object
}

// function to create or update the secret in the k8s cluster
// if the secret already exists, it will update the secret with a new password
// if the secret does not exist, it will create a new secret with a new password
// return true if the secret is created or updated successfully
func (r *AWSSecretGuardianReconciler) CreateUpdateK8SSecret(ctx context.Context, nameSpaceName string, secretName string, secretData map[string][]byte, create bool) (bool, error) {
	utcTime := time.Now().UTC()
	controllerAnnotation := map[string]string{"K8s-Secret-Rotation-Controller": utcTime.Format(time.RFC3339)} // create a new annotation for the secret object
	secretObj := &corev1.Secret{                                                                              // create a new secret object
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   nameSpaceName,
			Annotations: controllerAnnotation,
		},
		Data: secretData,
	}
	var err error
	if create { // check if the secret object needs to be created or updated
		err = r.Create(ctx, secretObj)
	} else {
		err = r.Update(ctx, secretObj)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
