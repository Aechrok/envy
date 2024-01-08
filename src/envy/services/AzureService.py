import json, os
import click
from azure.identity import EnvironmentCredential
from azure.keyvault.secrets import SecretClient


class Azure(object):
    """Azure Keyvault"""

    def __init__(self):
        super(Azure, self).__init__()

    def envy(self, verbose, command, name, mask, tenantID, clientID, clientSecret, keyvaultName):
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
        vault_url = f"https://{keyvaultName}.vault.azure.net"

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
                        click.secho(f"Secret is not in json format. {e}", fg='red', err=True)
                        exit(2)

                except Exception as e:
                    click.secho(f"Failed to evalute creds: {e}", fg='red', err=True)
                    exit(2)

            # If command follows, execute it
            if command:
                return {
                    "command": command, 
                    "verbose": verbose,
                    "mask": mask
                }
        else:
            click.secho("Missing required environmental variables.", fg='red', err=True)
            exit(2)