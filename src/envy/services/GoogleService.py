import json, os
import click
from google.cloud import secretmanager


class Google(object):
    """Google Secrets Manager"""

    def __init__(self):
        super(Google, self).__init__()

    def envy(self, verbose, command, name, mask, googleApplicationCredentials, googleProjectID, googleVersionID):
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
            click.secho(f"Failed to create Secret Manager client: {e}", fg='red', err=True)
            exit(2)

        if verbose > 0:
            click.secho("Processing credentials...", fg='yellow')
        secret_name = f"projects/{googleProjectID}/secrets/{name}/versions/{googleVersionID}"

        try:
            response = client.access_secret_version(request={"name": secret_name})
            if verbose > 0:
                click.secho("Credentials found, setting environment...", fg='yellow')
        except Exception as e:
            click.secho(f"Failed to retrieve the secret: {e}", fg='red', err=True)
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
            click.secho(f"Secret is not in json format. {e}", fg='red', err=True)
            exit(2)

        if command:
            return {
                "command": command, 
                "verbose": verbose,
                "mask": mask
            }