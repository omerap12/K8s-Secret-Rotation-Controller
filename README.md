# K8s Secret Rotation Controller

K8s Secret Rotation Controller is a Kubernetes controller designed to facilitate the automatic rotation of secrets within your Kubernetes cluster. This ensures that sensitive information remains secure and up-to-date, reducing the risk of exposure or misuse.

## Features

- **Automated Secret Rotation:** Automatically rotates secrets at specified intervals.
- **Customizable Rotation Policies:** Define custom rotation policies to meet your security requirements.
- **Integration with AWS Secret Manager:** Supports seamless integration with AWS Secret Manager.
- **Advanced Secret Specifications:** Configure advanced settings such as key lengths, regions, TTL (Time to Live), and specific keys to be rotated.

## Deployment

TBD

## Manifest Example

```yaml
apiVersion: secretguardian.omerap12.com/v1alpha1
kind: AWSSecretGuardian
metadata:
  labels:
    app.kubernetes.io/name: awssecretguardian
    app.kubernetes.io/instance: awssecretguardian-sample
    app.kubernetes.io/part-of: k8s-secret-rotation-controller
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: k8s-secret-rotation-controller
  name: awssecretguardian-sample-3
  namespace: omer
spec:
  length: 16 # Length of each key in the secret
  name: "test-1" # Name of the secret that will be created in AWS Secret Manager
  region: "us-east-1" # AWS region
  ttl: 3600 # Rotation interval in seconds
  keys: # Keys that will be created inside the secret
    - "key1"
    - "key2"
    - "key3"
```

