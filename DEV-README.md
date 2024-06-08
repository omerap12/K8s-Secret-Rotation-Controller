# k8s-secret-rotation-controller
The k8s-secret-rotation-controller controller is a Kubernetes operator designed to manage secrets stored in AWS Secret Manager. It automates the rotation process of these secrets, ensuring they are regularly updated and synchronized with their Kubernetes counterparts. This controller integrates with AWS services such as STS (Security Token Service) and Secrets Manager to securely manage credentials and secret data.

## Description
The k8s-secret-rotation-controller controller is a Kubernetes operator built to simplify the management and rotation of secrets stored in AWS Secret Manager. This controller operates by reconciling custom resources of type `AWSSecretGuardian`, which define the parameters for secret rotation.

Here's a brief overview of the key functionalities:

1. **Secret Rotation:** The controller periodically rotates secrets stored in AWS Secret Manager according to predefined schedules specified in the `AWSSecretGuardian` custom resources.

2. **AWS Integration:** It interacts with AWS services such as STS (Security Token Service) to authenticate and obtain user ARNs and Secrets Manager to manage secrets.

3. **Kubernetes Integration:** The controller ensures synchronization between secrets stored in AWS and their Kubernetes counterparts. It creates or updates Kubernetes secrets based on the rotated values from AWS Secret Manager.

4. **Customizable Rotation Parameters:** Users can define rotation parameters such as secret name, region, rotation interval (TTL), and keys (attributes) within the `AWSSecretGuardian` custom resources.

5. **Error Handling:** The controller includes error handling mechanisms to manage various scenarios, such as failed authentication, secret creation/update errors, and AWS service errors.

6. **Logging and Monitoring:** It provides detailed logging using the Kubernetes logging framework to facilitate monitoring and troubleshooting.

By leveraging the AWSSecretGuardian controller, Kubernetes users can streamline the management of secrets stored in AWS, ensuring robust security practices and regulatory compliance.

## Getting Started
You’ll need a Kubernetes cluster to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.
**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster
1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/k8s-secret-rotation-controller:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/k8s-secret-rotation-controller:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/),
which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

