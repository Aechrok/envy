import json, os
import click
from dopplersdk import DopplerSDK


class Doppler(object):
    """Doppler Secrets Manager"""

    def __init__(self):
        super(Doppler, self).__init__()

    def envy(self, verbose, command, name, mask, dopplerProject, dopplerConfig, dopplerToken):
        if verbose > 0:
            click.secho("Doppler selected.", fg='green')

        # Pre-flight checks
        if dopplerProject is None:
            click.secho("Missing: Doppler Project", fg='red', err=True)
            exit(2)
        if dopplerConfig is None:
            click.secho("Missing: Doppler Config", fg='red', err=True)
            exit(2)
        if dopplerToken is None:
            click.secho("Missing: Doppler Token", fg='red', err=True)
            exit(2)

        creds = {}

        if dopplerProject and dopplerConfig and dopplerToken:
            try:
                if verbose > 0:
                    click.secho("Processing credentials...", fg='yellow')
                doppler = DopplerSDK()
                doppler.set_access_token(dopplerToken)

                if verbose > 0:
                    click.secho("Credentials found, retrieving secret...", fg='yellow')
                results = doppler.secrets.get(
                    project = dopplerProject,
                    config = dopplerConfig,
                    name = name
                )
            except Exception as e:
                click.secho(f"Missing doppler credentials: {e}", fg='red', err=True)

            try:
                if verbose > 0:
                    click.secho("Secret retrieved, setting environment...", fg='yellow')
                creds = json.loads(results.value['computed'])
                for k,v in creds.items():
                    os.environ[str(k)] = str(v)
            except Exception as e:
                click.secho(f"Failed to retrieve the secret: {e}", fg='red', err=True)


            if command:
                return {
                    "command": command, 
                    "verbose": verbose,
                    "mask": mask
                }