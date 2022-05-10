import os, json, logging, subprocess
import click

from azure.identity import EnvironmentCredential
from azure.keyvault.secrets import SecretClient

AZURE_TENANT_ID=os.environ.get('AZURE_TENANT_ID')
AZURE_CLIENT_ID=os.environ.get('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET=os.environ.get('AZURE_CLIENT_SECRET')
AZURE_KEYVAULT_NAME=os.environ.get('AZURE_KEYVAULT_NAME')
AZURE_SECRET_NAME=os.environ.get('AZURE_SECRET_NAME')

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
@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-n', '--secret-name', 'name', default=AZURE_SECRET_NAME, help='\b\nName of the secret to be queried.\n[env: AZURE_SECRET_NAME]={}'.format(AZURE_SECRET_NAME))
@click.option('--azure', 'azure', is_flag=True, help='\b\nUse Azure Keyvault.\n')
@click.option('--aws', 'aws', is_flag=True, help='\b\nUse AWS Key Management Service.\n')
@click.option('--google', 'google', is_flag=True, help='\b\nUse Google Cloud Key Management Service.\n')
@click.option('--azure-tenant-id', 'tenantID', default=AZURE_TENANT_ID, help='\b\nThe tenant id of the service principal used for authorization.\n[env: AZURE_TENANT_ID]={}'.format(AZURE_TENANT_ID))
@click.option('--azure-client-id', 'clientID', default=AZURE_CLIENT_ID, help='\b\nThe application id of the service principal used for authorization.\n[env: AZURE_CLIENT_ID]={}'.format(AZURE_CLIENT_ID))
@click.option('--azure-client-secret', 'clientSecret', default=AZURE_CLIENT_SECRET, help='\b\nThe secret of the service principal used for authorization.\n[env: AZURE_CLIENT_SECRET]')
@click.option('--azure-keyvault-name', 'keyvaultName', default=AZURE_KEYVAULT_NAME, help='\b\nThe name of Azure KeyVault (in the public cloud) where the secret lives.\n[env: AZURE_KEYVAULT_NAME]={}'.format(AZURE_KEYVAULT_NAME))
@click.option('-m', '--mask', 'mask', multiple=True, help='Environment variable that should be masked.')
@click.option('-v', '--verbose', 'verbose', count=True, help='Increase the verbosity of log messages.')
@click.option('-c', '--command', 'command', help='Command to run within the secrets environment.')
def main(name, azure, aws, google, tenantID, clientID, clientSecret, keyvaultName, mask, verbose, command):
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
        if verbose > 0:
            click.secho("Azure selected.", fg='green')

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
                    creds = json.loads(client.get_secret(name).value)
                    for k,v in creds.items():
                        os.environ[str(k)] = str(v)

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
        if verbose > 0:
            click.secho("AWS selected.", fg='green')

# Google
    elif google:
        if verbose > 0:
            click.secho("Google selected.", fg='green')

    else:
        click.secho("Missing destination service.", fg='red', err=True)
        exit(2)
if __name__ == '__main__':
    main()