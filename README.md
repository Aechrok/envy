ENVy
=====

Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from Azure keyvault.

Concept based on Jakub Fijałkowski's [KVENV](https://github.com/jakubfijalkowski/kvenv).

```
Usage: envy [OPTIONS]

  ENVy

  Simple cli tool to run arbitrary code using environmental variables
  retrieved as a json object from Azure keyvault.

  Created by: Lee Martin (https://github.com/Aechrok)

Options:
  -n, --secret-name TEXT      Name of the secret to be queried.
                              [env: AZURE_SECRET_NAME]
  --azure-tenant-id TEXT      The tenant id of the service principal used for authorization.
                              [env: AZURE_TENANT_ID]
  --azure-client-id TEXT      The application id of the service principal used for authorization.
                              [env: AZURE_CLIENT_ID]
  --azure-client-secret TEXT  The secret of the service principal used for authorization.
                              [env: AZURE_CLIENT_SECRET]
  --azure-keyvault-name TEXT  The name of Azure KeyVault (in the public cloud) where the secret lives.
                              [env: AZURE_KEYVAULT_NAME]
  -m, --mask TEXT             Environment variable that should be masked.
  -c, --command TEXT          Command to run within the secrets environment.
  -h, --help                  Show this message and exit.
  ```

## Environment Setup
#### Azure
To avoid the dreaded "God Account", a minimum of two Service Principals are required: One to access the Key Vault to retrieve the environment secret, and the second with write permissions to make the desired changes.

#### Key Vault
Environments are stored as a single JSON object within a keyvault secret

```json
{
    "ARM_TENANT_ID":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "ARM_CLIENT_ID":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "ARM_CLIENT_SECRET":"XXXXXXXXXXXX"
}
```

#### CI/CD
However you choose to do it, five(5) environmental variables are required to run ENVy: `AZURE_SECRET_NAME`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_KEYVAULT_NAME`. These can be injected as a Kubernetes secret, or otherwise pushed into the environment that is running ENVy.

If you are using tools such as [Atlantis](https://www.runatlantis.io/) where the repository name is provided as a variable at runtime, it is preferable to name the keyvault secret the same as the repository so that you can run workflows such as:

```shell
envy -n $BASE_REPO_NAME -c 'terraform init'
```

This allows for multi-tenant use with Azure without exposing the credentials for the Service Principals with access.

## Features
#### Masking
Masking is supported to hide a variable from the child command. Adding a `-m` or `--mask` switch with the matching variable name will achieve this.

```shell
envy -n ... --mask VARIABLE -c 'child process'
```