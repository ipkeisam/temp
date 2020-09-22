import requests
import json
import boto3
import base64
import os
from botocore.exceptions import ClientError

def sendRequest(access_key_id,secret_access_key,account_id,service_account,account_name):
    is_iam_playbook_invoked = False
    url = os.environ['ANSIBLE_TOWER_URL']
    job_id = ''
    payload = {
        "extra_vars": {
            "aws_account_name": account_name,
            "aws_account_number": account_id,
            "access_key": access_key_id,
            "secret_key": secret_access_key            
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    if '201' in str(response.status_code):
        is_iam_playbook_invoked = True
        json_response_dict = json.loads(response.text)
        job_id = json_response_dict['id']
    print(response.status_code)
        
    return is_iam_playbook_invoked,job_id

def get_secret(secretname,regionname):

    print(secretname)
    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname,
        endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT']
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretname
        )
    except ClientError as e:
        print("Exception raised:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret

def lambda_handler(event,context):

    tower_job_ids = event['tower_job_ids']

    is_iam_playbook_invoked = False
    #Retrieve account id from State Machine event variable
    account_id = event['account_id']

    #Retrieve account name from State Machine event variable
    account_name = event['account_name']
    print(account_name)
    
    #Secrets Manager will be setup in US-East-1 within master account
    secret_name =  os.environ['IAMUserName'] + "-" + account_id
    region_name = os.environ['SecretsManagerRegionName']

    # retrieve Secret for IAM role from AWS Secrets Manager
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    access_key_id = response_dict['access_key_id']
    secret_access_key = response_dict['secret_access_key']

    secret_name = os.environ['IAMServiceAccountCreds']
    region_name = os.environ['SecretsManagerRegionName']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account_IAM = response_dict['IAMServiceAccount']
    
    # Invoke tower url
    (is_iam_playbook_invoked,job_id) = sendRequest(access_key_id,secret_access_key,account_id,service_account_IAM,account_name)
    print(is_iam_playbook_invoked)
    print(job_id)
    tower_job_ids['IAM Playbook Execution Status'] = job_id
    event['tower_job_ids'] = tower_job_ids
    event['is_iam_playbook_invoked'] = is_iam_playbook_invoked
    return event