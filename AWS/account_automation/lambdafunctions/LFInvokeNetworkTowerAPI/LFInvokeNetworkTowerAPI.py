import requests
import json
import boto3
import base64
import os
import time
from botocore.exceptions import ClientError

def sendRequest(network_parameters,service_account,deployregion):
    is_network_playbook_invoked = False
    url = os.environ['NETWORK_TOWER_URL']
    job_id = ''
    payload = {
        "extra_vars": {
            "account_profile": network_parameters['account_profile'],
            "aws_region": deployregion,
            "vpc_name": network_parameters['vpc_name'],
            "env": network_parameters['env'],

            "state": network_parameters['state'],
            "ticket_number": 'FOR AWS NEW ACCOUNT ' + network_parameters['account_profile'],
            "addtl_az": 0
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    if '201' in str(response.status_code):
        is_network_playbook_invoked = True
        json_response_dict = json.loads(response.text)
        job_id = json_response_dict['id']
    print(response.status_code)
    return is_network_playbook_invoked,job_id

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
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret

def lambda_handler(event,context):

    network_parameters = {}
    vpc_cidr_block = []
    networkregions = []
    is_network_playbook_invoked = False
    are_network_vpcs_created = {}
    tower_job_ids = event['tower_job_ids']

    #Retrieve parameters requird for Network module from State Machine event variable
    account_id = event['account_id']
    account_name = event['account_name'].lower()
    state = 'present'
    vpc_name = 'vpc1'
    env = event['environment_type'].lower()
    
    #temporary fix to set env type as prod instead of prd
    if env == "prd":
        env = "prod"

    #network regions where VPC should be setup
    networkregions = event['network_regions']

    print(account_name)

    network_parameters['state'] = state
    network_parameters['account_profile'] = account_name
    network_parameters['vpc_name'] = vpc_name
    network_parameters['env'] = env
    #network_parameters['vpc_cidr_block'] = vpc_cidr_block
    #Secrets Manager will be setup in US-East-1 within master account
    secret_name = os.environ['NetworkServiceAccountCreds']
    region_name = os.environ['SecretsManagerRegionName']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account = response_dict['IAMServiceAccount']

    region_mapping = {'us-east-1':'e1', 'us-east-2':'e2', 'us-west-1':'w1', 'us-west-2':'w2'}
    # Invoke tower url per region
    length = len(networkregions)
    for i in range(length):
        deployregion = networkregions[i]
        are_network_vpcs_created.update({deployregion:False})
        (is_network_playbook_invoked,job_id) = sendRequest(network_parameters,service_account,deployregion)
        are_network_vpcs_created.update({deployregion:is_network_playbook_invoked})
        print(is_network_playbook_invoked)
        print(job_id)
        playbook_var = 'Network Playbook for ' + deployregion + ' Execution Status'
        tower_job_ids[playbook_var] = job_id
        if i < length-1:
            time.sleep(60)
    event['are_network_vpcs_created'] = are_network_vpcs_created
    event['tower_job_ids'] = tower_job_ids
    return event