from __future__ import print_function
import requests
import json
import boto3
import base64
import os
from botocore.exceptions import ClientError

def sendRequest(account_email,service_account,account_name):

    create_email_distribution_successful = False
    url = os.environ['EMAILDISTRO_ANSIBLE_TOWER_URL']

    payload = {
        "extra_vars": {
            "aws_account_alias": account_name,
            "aws_account_email": account_email
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    print(response.text)
    response_status = response.status_code
    if '201' in str(response_status):
        create_email_distribution_successful = True
    return create_email_distribution_successful

def get_secret(secretname,regionname):

    print(secretname)
    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretname
        )
    except ClientError as e:
        print("Exception raised:", e)
        raise
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret

def lambda_handler(event,context):

    is_email_distribution_created = False
    #Retrieve account email from State Machine event variable
    account_email = event['account_email'].lower()

    #Retrieve account name from State Machine event variable
    account_name = event['account_name'].lower()
    print(account_name)
    
    #Secrets Manager will be setup in US-East-1 within master account
    secret_name = os.environ['AnsibleTowerAccountCreds']
    region_name = os.environ['SecretsManagerRegionName']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account = response_dict['IAMServiceAccount']
    
    # Invoke tower url
    is_email_distribution_created = sendRequest(account_email,service_account,account_name)
    event['is_email_distribution_created'] = is_email_distribution_created
    return event