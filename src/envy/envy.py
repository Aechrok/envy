import os, json, logging, subprocess, base64
import click

import services.AzureService
import services.AwsService
import services.GoogleService
import services.DopplerService

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
DOPPLER_PROJECT=os.environ.get('DOPPLER_PROJECT')
DOPPLER_CONFIG=os.environ.get('DOPPLER_CONFIG')
DOPPLER_TOKEN=os.environ.get('DOPPLER_TOKEN')

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
@click.option('-n', '--secret-name', 'name', metavar='<string>', required=True, default=SECRET_NAME, help=f'\b\nName of the secret to be queried.\n[env: SECRET_NAME]={SECRET_NAME}')
@click.option('-m', '--mask', 'mask', metavar='<string>', multiple=True, help=f'Environment variable that should be masked.')
@click.option('-v', '--verbose', 'verbose', metavar='<string>', count=True, help=f'Increase the verbosity of log messages.')
@click.option('-c', '--command', 'command', metavar='<string>', help=f'Command to run within the secrets environment.')
@click.option('--azure', 'azure', is_flag=True, help=f'\b\nUse Azure Keyvault.\n')
@click.option('--azure-tenant-id', 'tenantID', metavar='<string>', default=AZURE_TENANT_ID, help=f'\b\nThe tenant id of the service principal used for authorization.\n[env: AZURE_TENANT_ID]={AZURE_TENANT_ID}')
@click.option('--azure-client-id', 'clientID', metavar='<string>', default=AZURE_CLIENT_ID, help=f'\b\nThe application id of the service principal used for authorization.\n[env: AZURE_CLIENT_ID]={AZURE_CLIENT_ID}')
@click.option('--azure-client-secret', 'clientSecret', metavar='<string>', default=AZURE_CLIENT_SECRET, help=f'\b\nThe secret of the service principal used for authorization.\n[env: AZURE_CLIENT_SECRET]={AZURE_CLIENT_SECRET}')
@click.option('--azure-keyvault-name', 'keyvaultName', metavar='<string>', default=AZURE_KEYVAULT_NAME, help=f'\b\nThe name of Azure KeyVault (in the public cloud) where the secret lives.\n[env: AZURE_KEYVAULT_NAME]={AZURE_KEYVAULT_NAME}')
@click.option('--aws', 'aws', is_flag=True, help=f'\b\nUse AWS Secrets Manager Service.\n')
@click.option('--aws-access-key-id', 'awsAccessKeyID', metavar='<string>', default=AWS_ACCESS_KEY_ID, help=f'\b\nThe AWS access key ID.\n[env: AWS_ACCESS_KEY_ID]={AWS_ACCESS_KEY_ID}')
@click.option('--aws-secret-access-key', 'awsSecretAccessKey', metavar='<string>', default=AWS_SECRET_ACCESS_KEY, help=f'\b\nThe AWS secret access key.\n[env: AWS_SECRET_ACCESS_KEY]={AWS_SECRET_ACCESS_KEY}')
@click.option('--aws-region', 'awsRegion', metavar='<string>', default=AWS_REGION, help=f'\b\nThe AWS region your secret is located in.\n[env: AWS_REGION]={AWS_REGION}')
@click.option('--google', 'google', is_flag=True, help=f'\b\nUse Google Cloud Secret Manager Service.\n')
@click.option('--google-application-credentials', 'googleApplicationCredentials', metavar='<string>', default=GOOGLE_APPLICATION_CREDENTIALS, help=f'\b\nThe path to the credentials json file.\n[env: GOOGLE_APPLICATION_CREDENTIALS]={GOOGLE_APPLICATION_CREDENTIALS}')
@click.option('--google-project-id', 'googleProjectID', metavar='<string>', default=GOOGLE_PROJECT_ID, help=f'\b\nGoogle Cloud project ID (e.g. "my-project").\n[env: GOOGLE_PROJECT_ID]={GOOGLE_PROJECT_ID}')
@click.option('--google-version-id', 'googleVersionID', metavar='<string>', default=GOOGLE_VERSION_ID, help=f'\b\nCloud KMS secret version (e.g. "1").\n[env: GOOGLE_VERSION_ID]={GOOGLE_VERSION_ID}')
@click.option('--doppler', 'doppler', is_flag=True, help=f'\b\nUse Doppler Secret Manager Service.\n')
@click.option('--doppler-project', 'dopplerProject', metavar='<string>', default=DOPPLER_PROJECT, help=f'\b\nDoppler project where the secret lives.\n[env: DOPPLER_PROJECT]={DOPPLER_PROJECT}')
@click.option('--doppler-config', 'dopplerConfig', metavar='<string>', default=DOPPLER_CONFIG, help=f'\b\nDoppler config for the specific environment.\n[env: DOPPLER_CONFIG]={DOPPLER_CONFIG}')
@click.option('--doppler-token', 'dopplerToken', metavar='<string>', default=DOPPLER_TOKEN, help=f'\b\nDoppler service token.\n[env: DOPPLER_TOKEN]={DOPPLER_TOKEN}')
def main(name, azure, aws, google, doppler, # Service flags
         awsAccessKeyID, awsSecretAccessKey, awsRegion, # AWS
         tenantID, clientID, clientSecret, keyvaultName, # Azure
         googleApplicationCredentials, googleProjectID, googleVersionID, # Google
         dopplerProject, dopplerConfig, dopplerToken, # Doppler
         mask, verbose, command):
    """
    ENVy\n
    Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from various secret managers.
    
    Created by: Lee Martin (https://github.com/Aechrok)
    """

    # Pre-flight checks
    if name is None:
        click.secho("Missing: Secret Name", fg='red', err=True)
        exit(2)

# Azure
    if azure:
        svc = Azure()
        res = svc.envy(verbose, command, name, mask, tenantID, clientID, clientSecret, keyvaultName)
        if res.get('command', None):
            command_run(res['command'], res['verbose'], res['mask'])

# AWS
    elif aws:
        svc = AWS()
        res = svc.envy(verbose, command, name, mask, awsAccessKeyID, awsSecretAccessKey, awsRegion)
        if res.get('command', None):
            command_run(res['command'], res['verbose'], res['mask'])

# Google
    elif google:
        svc = Google()
        res = svc.envy(verbose, command, name, mask, googleApplicationCredentials, googleProjectID, googleVersionID)
        if res.get('command', None):
            command_run(res['command'], res['verbose'], res['mask'])

    elif doppler:
        svc = Doppler()
        res = svc.envy(verbose, command, name, mask, dopplerProject, dopplerConfig, dopplerToken)
        if res.get('command', None):
            command_run(res['command'], res['verbose'], res['mask'])

    else:
        click.secho("Missing: Azure, AWS, Google, or Doppler flags.", fg='red', err=True)
        exit(2)
if __name__ == '__main__':
    main()