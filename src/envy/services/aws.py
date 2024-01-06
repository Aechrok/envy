import json, os
import click
import boto3
from botocore.exceptions import ClientError


class AWS(object):
    """AWS Secrets Manager"""

    def __init__(self):
        super(AWS, self).__init__()

    def envy(self, verbose, command, name, mask, awsAccessKeyID, awsSecretAccessKey, awsRegion):
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
                    click.secho(f"Failed to decrypt: {e}", fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                    # An error occurred on the server side.
                    click.secho(f"Internal Service Error: {e}", fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InvalidParameterException':
                    # You provided an invalid value for a parameter.
                    click.secho(f"Invalid parameter: {e}", fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'InvalidRequestException':
                    # You provided a parameter value that is not valid for the current state of the resource.
                    click.secho(f"Invalid request: {e}", fg='red')
                    exit(2)
                elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # We can't find the resource that you asked for.
                    click.secho(f"Resource not found: {e}", fg='red')
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
                    click.secho(f"Secret is not in json format. {e}", fg='red', err=True)
                    exit(2)
            else:
                click.secho("No secret found.", fg='red')
                exit(2)

        if command:
            return {
                "command": command, 
                "verbose": verbose,
                "mask": mask
            }