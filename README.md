ENVy
=====

Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from Azure keyvault.

Concept based on Jakub Fijałkowski's [KVENV](https://github.com/jakubfijalkowski/kvenv).

```
Usage: envy --secret-name <name> <options>

  ENVy

  Simple cli tool to run arbitrary code using environmental variables
  retrieved as a json object from Azure keyvault.

  Created by: Lee Martin (https://github.com/Aechrok)

Options:
  -n, --secret-name <string>                      Name of the secret to be queried.
                                                  [env: SECRET_NAME]=None  [required]
  -m, --mask <string>                             Environment variable that should be masked.
  -v, --verbose                                   Increase the verbosity of log messages.
  -c, --command <string>                          Command to run within the secrets environment.

  --azure                                         Use Azure Keyvault.
  --azure-tenant-id <string>                      The tenant id of the service principal used for authorization.
                                                  [env: AZURE_TENANT_ID]
  --azure-client-id <string>                      The application id of the service principal used for authorization.
                                                  [env: AZURE_CLIENT_ID]
  --azure-client-secret <string>                  The secret of the service principal used for authorization.
                                                  [env: AZURE_CLIENT_SECRET]
  --azure-keyvault-name <string>                  The name of Azure KeyVault (in the public cloud) where the secret lives.
                                                  [env: AZURE_KEYVAULT_NAME]

  --aws                                           Use AWS Secrets Manager Service.
  --aws-access-key-id <string>                    The AWS access key ID.
                                                  [env: AWS_ACCESS_KEY_ID]
  --aws-secret-access-key <string>                The AWS secret access key.
                                                  [env: AWS_SECRET_ACCESS_KEY]
  --aws-region <string>                           The AWS region your secret is located in.
                                                  [env: AWS_REGION]

  --google                                        Use Google Cloud Secret Manager Service.
  --google-application-credentials <string>       The path to the credentials json file.
                                                  [env: GOOGLE_APPLICATION_CREDENTIALS]
  --google-project-id <string>                    Google Cloud project ID (e.g. "my-project").
                                                  [env: GOOGLE_PROJECT_ID]
  --google-version-id <string>                    Cloud KMS secret version (e.g. "1").
                                                  [env: GOOGLE_VERSION_ID]
  -h, --help                                      Show this message and exit.
  ```

## Capabilities
[X] Azure Key Vault
[X] Google Cloud Secrets Manager
[X] AWS Secrets Manager
[X] Variable masking
[ ] Integration tests
[X] JSON-based keys

## Environment Setup
### Azure
#### Service Principals
A service principal with read-only access to the Key Vault to retrieve the environment secret will be required. Presently, ENVy does not support managed identites, so a client/secret is required. This can be achieved using `app registrations`.

More information can be found here: [https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

#### Key Vault
Environments are stored as a single JSON object within a keyvault secret. ENVy will specifically only grab the current version of the key.

```json
{
    "SECRET_ONE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_TWO":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_THREE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
}
```

### AWS
#### IAM Users
You must have an IAM user with permissions on AWS Secrets Manager.

#### Secrets Manager
Your secret should be created here. You can either use the key/value pair or drop json into the plaintext for the same effect. More information can be found here: [https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html) and [https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)

```json
{
    "SECRET_ONE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_TWO":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_THREE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
}
```

### Google
#### Service Accounts
A service account is required with permissions to access Google Cloud Secrets Manager and it's secrets. This account will generate the credentials JSON file.

More information can be found here: [https://cloud.google.com/iam/docs/creating-managing-service-account-keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)

#### Google Application Credentials
A google JSON file is required and must be located in the same folder or a child folder. Parent folders will fail to locate the key.

#### Cloud Secrets Manager
Google Secrets are versioned so you will need to know the version of the key that you are looking for. ENVy will default to version 1 if none is provided.

```json
{
    "SECRET_ONE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_TWO":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "SECRET_THREE":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
}
```

## CI/CD
However you choose to do it, all options for a particular service are required to run ENVy. These are prefixed with the service name: (i.e. `--aws`, `--aws-access-key-id`, `--aws-secret-access-key`, and `--aws-region`). These can be injected as a Kubernetes secret, or otherwise pushed into the environment that is running ENVy using options found in the help `./envy -h`.

If you are using tools such as [Atlantis](https://www.runatlantis.io/) where the repository name is provided as a variable at runtime, it is preferable to name the secret the same as the repository so that you can run workflows such as:

```shell
envy -n $BASE_REPO_NAME -c 'terraform init'
```

This allows for multi-tenant use without exposing the credentials for the primary accounts with access.

## Features
#### Verbosity
Typically, there are no messages for successful actions. In the event that you require more information, specifically to figure out where a failure may be occurring, adding a `-v` or `--verbose` switch will display messages at each stage.

```shell
#> envy ... --verbose -c '...'
Environmental variables found...
Processing credentials...
Credentials found, setting environment...
Processing commands...
```

#### Masking
Masking is supported to hide a variable from the child command. Adding a `-m` or `--mask` switch with the matching variable name will achieve this. Multiple masking variables are permitted.

```shell
#> envy ... --mask VARIABLE -c 'echo $VARIABLE'
XXXXXX_MASKED_XXXXXX
```

## Issues and Help
Help is provided along with the tool:
```
envy -h
```
If you experience bugs or issues, you can create an issue here: [https://github.com/Aechrok/envy/issues](https://github.com/Aechrok/envy/issues)