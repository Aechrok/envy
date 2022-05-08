import os, json, logging, subprocess
import click

from azure.identity import EnvironmentCredential
from azure.keyvault.secrets import SecretClient

AZURE_TENANT_ID=os.environ.get('AZURE_TENANT_ID')
AZURE_CLIENT_ID=os.environ.get('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET=os.environ.get('AZURE_CLIENT_SECRET')
AZURE_KEYVAULT_NAME=os.environ.get('AZURE_KEYVAULT_NAME')
AZURE_SECRET_NAME=os.environ.get('AZURE_SECRET_NAME')

logging.basicConfig()
log = logging.getLogger("Envy")
log.setLevel(logging.INFO)


def command_run(cmd, mask):
    os.environ[str(mask)] = "XXXXXX_MASKED_XXXXXX"
    try:
        log.info("Processing commands...")
        result = subprocess.run(cmd, shell=True)
    except Exception as e:
        log.error("Failed execute command: {}: {}".format(cmd, result.stderr))


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-n', '--secret-name', 'name', default=AZURE_SECRET_NAME, help='\b\nName of the secret to be queried.\n[env: AZURE_SECRET_NAME]={}'.format(AZURE_SECRET_NAME))
@click.option('--azure-tenant-id', 'tenantID', default=AZURE_TENANT_ID, help='\b\nThe tenant id of the service principal used for authorization.\n[env: AZURE_TENANT_ID]={}'.format(AZURE_TENANT_ID))
@click.option('--azure-client-id', 'clientID', default=AZURE_CLIENT_ID, help='\b\nThe application id of the service principal used for authorization.\n[env: AZURE_CLIENT_ID]={}'.format(AZURE_CLIENT_ID))
@click.option('--azure-client-secret', 'clientSecret', default=AZURE_CLIENT_SECRET, help='\b\nThe secret of the service principal used for authorization.\n[env: AZURE_CLIENT_SECRET]')
@click.option('--azure-keyvault-name', 'keyvaultName', default=AZURE_KEYVAULT_NAME, help='\b\nThe name of Azure KeyVault (in the public cloud) where the secret lives.\n[env: AZURE_KEYVAULT_NAME]={}'.format(AZURE_KEYVAULT_NAME))
@click.option('-m', '--mask', 'mask', help='Environment variable that should be masked.')
@click.option('-c', '--command', 'command', help='Command to run within the secrets environment.')
def main(name, tenantID, clientID, clientSecret, keyvaultName, mask, command):
    """
    ENVy\n
    Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from Azure keyvault.
    
    Created by: Lee Martin (https://github.com/Aechrok)
    """

    # Pre-flight checks
    if name is None:
        click.secho("Missing: Secret Name", fg='red', err=True)
        exit(2)
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
                log.info('Environmental credentials found.')
            except Exception as e:
                log.warning("No environmental credentials clientId|clientSecret|tenantId found.")

        # Create client object
        if credentials:
            log.info("Processing credentials...")
            client = SecretClient(vault_url=vault_url, credential=credentials)

        # Load all variables from the Azure KV secret into the environment
        if client:
            log.info("Credentials found, setting environment...")
            try:
                creds = json.loads(client.get_secret(name).value)
                for k,v in creds.items():
                    os.environ[str(k)] = str(v)

            except Exception as e:
                log.error("Failed to evalute creds: {}".format(e))

        # If command follows, execute it
        if command:
            command_run(command, mask)

    else:
        log.error("Missing a required environmental variable.")
if __name__ == '__main__':
    main()