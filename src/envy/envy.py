import os, json, logging, subprocess, base64
import click

SECRET_NAME=os.environ.get('SECRET_NAME')
AZURE_TENANT_ID=os.environ.get('AZURE_TENANT_ID')
AZURE_CLIENT_ID=os.environ.get('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET=os.environ.get('AZURE_CLIENT_SECRET')
AZURE_KEYVAULT_NAME=os.environ.get('AZURE_KEYVAULT_NAME')
AWS_ACCESS_KEY_ID=os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY=os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION=os.environ.get('AWS_REGION')
GOOGLE_APPLICATION_CREDENTIALS=os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
GOOGLE_PROJECT_ID=os.environ.get('GOOGLE_PROJECT_ID')
GOOGLE_VERSION_ID=os.environ.get('GOOGLE_VERSION_ID')

def command_run(cmd, verbose, mask):
    for var in mask:
        os.environ[str(var)] = "XXXXXX_MASKED_XXXXXX"
    try:
        if verbose > 0:
            click.secho("Processing commands...", fg='yellow')
        result = subprocess.run(cmd, shell=True)
    except Exception as e:
        click.secho("Failed execute command: {}: {}".format(cmd, result.stderr), fg='red', err=True)
        exit(2)

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.command(context_settings=CONTEXT_SETTINGS, options_metavar='--secret-name <name> <options>')
@click.option('-n', '--secret-name', 'name', metavar='<string>', required=True, default=SECRET_NAME, help='\b\nName of the secret to be queried.\n[env: SECRET_NAME]={}'.format(SECRET_NAME))
@click.option('-m', '--mask', 'mask', metavar='<string>', multiple=True, help='Environment variable that should be masked.')
@click.option('-v', '--verbose', 'verbose', metavar='<string>', count=True, help='Increase the verbosity of log messages.')
@click.option('-c', '--command', 'command', metavar='<string>', help='Command to run within the secrets environment.')
@click.option('--azure', 'azure', is_flag=True, help='\b\nUse Azure Keyvault.\n')
@click.option('--azure-tenant-id', 'tenantID', metavar='<string>', default=AZURE_TENANT_ID, help='\b\nThe tenant id of the service principal used for authorization.\n[env: AZURE_TENANT_ID]={}'.format(AZURE_TENANT_ID))
@click.option('--azure-client-id', 'clientID', metavar='<string>', default=AZURE_CLIENT_ID, help='\b\nThe application id of the service principal used for authorization.\n[env: AZURE_CLIENT_ID]={}'.format(AZURE_CLIENT_ID))
@click.option('--azure-client-secret', 'clientSecret', metavar='<string>', default=AZURE_CLIENT_SECRET, help='\b\nThe secret of the service principal used for authorization.\n[env: AZURE_CLIENT_SECRET]')
@click.option('--azure-keyvault-name', 'keyvaultName', metavar='<string>', default=AZURE_KEYVAULT_NAME, help='\b\nThe name of Azure KeyVault (in the public cloud) where the secret lives.\n[env: AZURE_KEYVAULT_NAME]={}'.format(AZURE_KEYVAULT_NAME))
@click.option('--aws', 'aws', is_flag=True, help='\b\nUse AWS Secrets Manager Service.\n')
@click.option('--aws-access-key-id', 'awsAccessKeyID', metavar='<string>', default=AWS_ACCESS_KEY_ID, help='\b\nThe AWS access key ID.\n[env: AWS_ACCESS_KEY_ID]={}'.format(AWS_ACCESS_KEY_ID))
@click.option('--aws-secret-access-key', 'awsSecretAccessKey', metavar='<string>', default=AWS_SECRET_ACCESS_KEY, help='\b\nThe AWS secret access key.\n[env: AWS_SECRET_ACCESS_KEY]={}'.format(AWS_SECRET_ACCESS_KEY))
@click.option('--aws-region', 'awsRegion', metavar='<string>', default=AWS_REGION, help='\b\nThe AWS region your secret is located in.\n[env: AWS_REGION]={}'.format(AWS_REGION))
@click.option('--google', 'google', is_flag=True, help='\b\nUse Google Cloud Secret Manager Service.\n')
@click.option('--google-application-credentials', 'googleApplicationCredentials', metavar='<string>', default=GOOGLE_APPLICATION_CREDENTIALS, help='\b\nThe path to the credentials json file.\n[env: GOOGLE_APPLICATION_CREDENTIALS]={}'.format(GOOGLE_APPLICATION_CREDENTIALS))
@click.option('--google-project-id', 'googleProjectID', metavar='<string>', default=GOOGLE_PROJECT_ID, help='\b\nGoogle Cloud project ID (e.g. "my-project").\n[env: GOOGLE_PROJECT_ID]={}'.format(GOOGLE_PROJECT_ID))
@click.option('--google-version-id', 'googleVersionID', metavar='<string>', default=GOOGLE_VERSION_ID, help='\b\nCloud KMS secret version (e.g. "1").\n[env: GOOGLE_VERSION_ID]={}'.format(GOOGLE_VERSION_ID))
def main(name, azure, aws, google, awsAccessKeyID, awsSecretAccessKey, awsRegion, tenantID, clientID, clientSecret, keyvaultName, googleApplicationCredentials, googleProjectID, googleVersionID, mask, verbose, command):
    """
    ENVy\n
    Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from Azure keyvault.
    
    Created by: Lee Martin (https://github.com/Aechrok)
    """

    # Pre-flight checks
    if name is None:
        click.secho("Missing: Secret Name", fg='red', err=True)
        exit(2)

# Azure
    if azure:
        from azure.identity import EnvironmentCredential
        from azure.keyvault.secrets import SecretClient

        if verbose > 0:
            click.secho("Azure selected.", fg='green')

        # Pre-flight checks
        if tenantID is None:
            click.secho("Missing: Azure Tenant ID", fg='red', err=True)
            exit(2)
        if clientID is None:
            click.secho("Missing: Azure Client ID", fg='red', err=True)
            exit(2)
        if clientSecret is None:
            click.secho("Missing: Azure Client Secret", fg='red', err=True)
            exit(2)
        if keyvaultName is None:
            click.secho("Missing: Key Vault Name", fg='red', err=True)
            exit(2)
        
        credentials = None
        client = None
        creds = {}
        vault_url = "https://%s.vault.azure.net" % keyvaultName

        # Ensure all required variables are set
        if tenantID and clientID and clientSecret and keyvaultName:
            # Create credentials
            if credentials is None:
                try:
                    credentials = EnvironmentCredential()
                    if verbose > 0:
                        click.secho("Environmental variables found...", fg='yellow')
                except Exception as e:
                    click.secho("No environmental credentials clientId|clientSecret|tenantId found.", fg='red', err=True)
                    exit(2)

            # Create client object
            if credentials:
                if verbose > 0:
                    click.secho("Processing credentials...", fg='yellow')
                client = SecretClient(vault_url=vault_url, credential=credentials)

            # Load all variables from the Azure KV secret into the environment
            if client:
                try:
                    if verbose > 0:
                        click.secho("Credentials found, setting environment...", fg='yellow')
                    try:
                        creds = json.loads(client.get_secret(name).value)
                        for k,v in creds.items():
                            os.environ[str(k)] = str(v)
                    except Exception as e:
                        click.secho("Secret is not in json format. {}".format(e), fg='red', err=True)
                        exit(2)

                except Exception as e:
                    click.secho("Failed to evalute creds: {}".format(e), fg='red', err=True)
                    exit(2)

            # If command follows, execute it
            if command:
                command_run(command, verbose, mask)
        else:
            click.secho("Missing required environmental variables.", fg='red', err=True)
            exit(2)

# AWS
    elif aws:
        import boto3
        from botocore.exceptions import ClientError

        if verbose > 0:
            click.secho("AWS selected.", fg='green')

        # Pre-flight checks
        if awsAccessKeyID is None:
            click.secho("Missing: AWS Access Key ID", fg='red', err=True)
            exit(2)
        if awsSecretAccessKey is None:
            click.secho("Missing: AWS Secret Access Key", fg='red', err=True)
            exit(2)
        if awsRegion is None:
            click.secho("Missing: AWS Region", fg='red', err=True)
            exit(2)

        if verbose > 0:
            click.secho("Processing credentials...", fg='yellow')
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=awsRegion)

        if client:
            if verbose > 0:
                click.secho("Setting environment...", fg='yellow')
            try:
                get_secret_value_response = client.get_secret_value(SecretId=name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DecryptionFailureException':
                    # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                    click.secho("Failed to decrypt: {}".format(e), fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                    # An error occurred on the server side.
                    click.secho("Internal Service Error: {}".format(e), fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InvalidParameterException':
                    # You provided an invalid value for a parameter.
                    click.secho("Invalid parameter: {}".format(e), fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InvalidRequestException':
                    # You provided a parameter value that is not valid for the current state of the resource.
                    click.secho("Invalid request: {}".format(e), fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # We can't find the resource that you asked for.
                    click.secho("Resource not found: {}".format(e), fg='red')
                    exit(2)
            
            # Decrypts secret using the associated KMS key.
            if 'SecretString' in get_secret_value_response:
                if verbose > 0:
                    click.secho("Credentials found, setting environment...", fg='yellow')
                try:
                    creds = json.loads(get_secret_value_response['SecretString'])
                    for k,v in creds.items():
                        os.environ[str(k)] = str(v)
                except Exception as e:
                    click.secho("Secret is not in json format. {}".format(e), fg='red', err=True)
                    exit(2)
            else:
                click.secho("No secret found.", fg='red')
                exit(2)

        if command:
            command_run(command, verbose, mask)

# Google
    elif google:
        from google.cloud import secretmanager

        if verbose > 0:
            click.secho("Google selected.", fg='green')

        # Pre-flight checks
        if googleApplicationCredentials is None:
            click.secho("Missing: Google Application Credentials.", fg='red', err=True)
            exit(2)
        if googleProjectID is None:
            click.secho("Missing: Google Project ID.", fg='red', err=True)
            exit(2)
        if googleVersionID is None:
            if verbose > 0:
                click.secho("Warning: Google Version ID missing. Setting to 1.", fg='yellow')
            googleVersionID = "1"

        try:
            client = secretmanager.SecretManagerServiceClient()
            if verbose > 0:
                click.secho("Environmental variables found...", fg='yellow')
        except Exception as e:
            click.secho("Failed to create Secret Manager client: {}".format(e), fg='red', err=True)
            exit(2)

        if verbose > 0:
            click.secho("Processing credentials...", fg='yellow')
        secret_name = f"projects/{googleProjectID}/secrets/{name}/versions/{googleVersionID}"

        try:
            response = client.access_secret_version(request={"name": secret_name})
            if verbose > 0:
                click.secho("Credentials found, setting environment...", fg='yellow')
        except Exception as e:
            click.secho("Failed to retrieve the secret: {}".format(e), fg='red', err=True)
            exit(2)

        # Will need to add crc32c checksum check...
        # crc32c = google_crc32c.Checksum()
        # crc32c.update(response.payload.data)
        # if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        #     click.secho("Data corruption detected.", fg='red', err=True)
        #     exit(2)
        try:
            creds = json.loads(response.payload.data.decode("UTF-8"))
            for k,v in creds.items():
                os.environ[str(k)] = str(v)
        except Exception as e:
            click.secho("Secret is not in json format. {}".format(e), fg='red', err=True)
            exit(2)

        if command:
            command_run(command, verbose, mask)

    else:
        click.secho("Missing: Azure, AWS, or Google flags.", fg='red', err=True)
        exit(2)
if __name__ == '__main__':
    main()