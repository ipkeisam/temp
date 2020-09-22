from __future__ import print_function
import boto3
import botocore
import time
import os
import json

def get_metadata(sourcebucket,oktametadata):

    s3 = boto3.resource('s3','us-east-1')
    try:
        obj = s3.Object(sourcebucket,oktametadata)
        return obj.get()['Body'].read().decode('utf-8') 
    except botocore.exceptions.ClientError as e:
        print("Error accessing the source bucket. Error : {}".format(e))
        return e

def create_provider(credentials, metadata, providername):
    is_okta_provider_created = False
    client = boto3.client('iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])

    try:
        response = client.create_saml_provider(
            SAMLMetadataDocument=metadata,
            Name=providername
        )
        print(response)
        if not 'Error' in response:
            is_okta_provider_created = True
        return is_okta_provider_created

    except botocore.exceptions.ClientError as e:
        print("Error creating provider. Error : {}".format(e))
        return is_okta_provider_created

def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            print("before assume role")
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def lambda_handler(event,context):
    event['is_provider_setup_complete'] = False
    print(event)
    account_id = event['account_id']
    print("Account Id:" + account_id)

    account_role = 'OrganizationAccountAccessRole'
    sourcebucket = os.environ['SourceBucket']
    oktadev = os.environ['OktaDevMetadata']
    oktaprod = os.environ['OktaProdMetadata']

    oktadevmetadata = oktadev + ".xml"
    oktaprodmetadata = oktaprod + ".xml"

    credentials = assume_role(account_id, account_role)

    # Create Okta Dev provider for new account
    devmetadata = get_metadata(sourcebucket,oktadevmetadata)
    is_okta_dev_provider_created = create_provider(credentials, devmetadata, "Okta")
    print("Okta Dev Provider created successfully:"+ str(is_okta_dev_provider_created))
    event['is_okta_dev_provider_created'] = is_okta_dev_provider_created
    
    # Create Okta Prod provider for new account
    prodmetadata = get_metadata(sourcebucket,oktaprodmetadata)
    is_okta_prod_provider_created = create_provider(credentials, prodmetadata, "OktaProd")
    print("Okta Prod Provider created successfully:"+ str(is_okta_prod_provider_created))

    event['is_okta_prod_provider_created'] = is_okta_prod_provider_created
    print("Okta SAML providers setup complete !!")

    event['is_provider_setup_complete'] = True

    return event