# Kubernetes Authentication

Kube-auth helps engineers get a well-done kube config for accessing Kubernetes clusters via Kubectl.

The workflows are:
* leads engineers to authentication process for credentials
* sources clusters information from AWS S3
* assembles contexts with cluster and user information. 

> :warning: **Please note :** When an engineer has Google Groups updated, Kube-auth need to be rerun to get user information up-to-date, otherwise the desired permission may not be delivered.  

## Attribution
This project is customized based on [k8s-auth-example](https://github.com/pusher/k8s-auth-example).

## Prerequisites

* Make sure the profile staging exists in your aws credential file (~/.aws/credentials), as

  ```
  [staging]
  aws_access_key_id = <YOUR_STAGING_AWS_ACCESS_KEY_ID>
  aws_secret_access_key = <YOUR_STAGING_AWS_SECRET_ACCESS_KEY>
  ```
  and in aws config file (~/.aws/config), as

  ```
  [staging]
  output = json
  region = us-west-2
  ```
  Read this [wiki](https://cr.houzz.net/w/dev-introduction/aws-setup/) if you don't know value of above variables.

* Be clear of functionality and environment of clusters you need access to. Please refer to [cluster chart](https://cr.houzz.net/w/be/kubernetes/use_kubernetes/) in *Kubernetes At Houzz* section .

## Usage

```
kube-auth --env <stg|prod> --cluster <batch|saas|main|mgmt|test|all> 
```
The app is going to open a webpage on the browser jumping to Google Authentication. Use the company email to log in, you are all set when the success message shows up. By default, the path to kube config is `~/.kube/config`.

Here are some common scenarios:

Example 1: A developer who has workloads, like RQ worker, running in the batch cluster of both staging and production. 
```
kube-auth --env stg --cluster batch
kube-auth --env prod --cluster batch
```

Example 2: A developer who is working on Kafka consumers running in the batch cluster and CRM running in the saas cluster. 
```
kube-auth --env stg --cluster batch --cluster saas
kube-auth --env prod --cluster batch --cluster saas
```

Example 3: A k8s admin who needs to manage all clusters. Run 
```
kube-auth --env stg --cluster all
kube-auth --env prod --cluster all
```

Example 4: An intern who only needs to experiment in the staging batch cluster.
```
kube-auth --env stg --cluster batch.
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
