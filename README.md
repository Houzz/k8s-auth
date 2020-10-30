# Kubernetes Authentication

Kube-auth helps engineers get a well-done kube config for accessing Kubernetes clusters via Kubectl.

## Use Cases
1. Initialize setup of the toolset by generating kube config and authentication
2. Redo authentication when the google groups a developer belongs to has been updated
3. Redo authentication when the developer was authenticated against the issuer in another place, e.g. Oauth2 Proxy for accessing Kubernetes Dashboard
4. Add more clusters which need to access to for new workloads  

## Workflows
* Leads engineers to authentication process for credentials
* Sources clusters information from AWS S3
* Assembles contexts with cluster and user information
* Update kube config

## Attribution
This project is customized based on [k8s-auth-example](https://github.com/pusher/k8s-auth-example).

## Prerequisites

* See the first two [prerequisites](https://github.com/Houzz/kube-atlas/tree/master/infra/toolset/README.md#prerequisites) of the toolset. 

## Usage

:warning: Run the below command in a clean shell, i.e. no prompt about k8s cluster and namespace introduced by kubie should appear.     

```
kube-auth --env <stg|prod> --fxnl <batch|saas|main|mgmt|test|all> 
```
The app is going to open a webpage on the browser jumping to Google Authentication. Use the company email to log in, you are all set when the success message shows up. By default, the path to kube config is `~/.kube/config`.

Here are some common scenarios:

Example 1: A developer who has workloads, like RQ worker, running in the batch cluster of both staging and production. 
```
kube-auth --env stg --fxnl batch
kube-auth --env prod --fxnl batch
```

Example 2: A developer who is working on Kafka consumers running in the batch cluster and CRM running in the saas cluster. 
```
kube-auth --env stg --fxnl batch --fxnl saas
kube-auth --env prod --fxnl batch --fxnl saas
```

Example 3: A developer who accessed dashboard of stg-batch 15 mins ago, and gets refresh token in kube config rotated when using kubectl  
```
kube-auth --env stg
```

Example 4: A developer who was added to a new group by his/her manager for some permissions in prod-batch cluster. 
```
kube-auth --env prod
```

Example 5: A k8s admin who needs to manage all clusters. Run 
```
kube-auth --env stg --fxnl all
kube-auth --env prod --fxnl all
```

Example 6: An intern who only needs to experiment in the staging batch cluster.
```
kube-auth --env stg --fxnl batch.
```

> :information_source: **Tips :** Run `kube-auth --help` for usage information of the app if you are not sure how to use the app.

## Communication

* Found a bug? Please open an issue.
* Have a feature request. Please open an issue.
* If you want to contribute, please submit a pull request

## Contributing
Please see our [Contributing](CONTRIBUTING.md) guidelines.

## License
This project is licensed under Apache 2.0 and a copy of the license is available [here](LICENSE).
