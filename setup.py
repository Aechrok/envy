from setuptools import setup, find_packages
from datetime import datetime
from pathlib import Path

NAME = "ENVy"
VERSION = "1.0.2"

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

REQUIRES = [
    'click',
    'azure-identity',
    'azure-keyvault',
    'azure-keyvault-secrets',
    'boto3',
    'google-cloud-secret-manager',
    'doppler-sdk'
    ]

setup(
    name=NAME,
    version=VERSION,
    description="""
    Simple cli tool to run arbitrary code using environmental variables retrieved as a json object from various common secret managers.
    """,
    author_email="lee@leemartin.us",
    packages=[
        'envy',
        'envy/services'
    ],
    zip_safe=False,
    include_package_data=True,
    install_requires=REQUIRES,
    tests_require=['pytest'],
    long_description=long_description,
    long_description_content_type = "text/markdown"
)