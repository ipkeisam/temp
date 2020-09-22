import requests
import json
import boto3,botocore
import base64
import os
from botocore.exceptions import ClientError

def sendRequest(job_id,service_account):
    is_job_successful = False
    url = os.environ['TOWER_URL'] + job_id
    print(url)
    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("GET", url, headers=headers)
    json_dict = json.loads(response.text)

    print(json_dict['name'])
    print(json_dict['status'])
    print(json_dict['failed'])

    if 'extra_vars' in json_dict:
        extra_vars = json_dict['extra_vars']
        json_extra_vars = json.loads(extra_vars)
        print(str(json_extra_vars))
    response_status = json_dict['status']
    if 'successful' in str(response_status):
        is_job_successful = True
    return is_job_successful

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

def send_towerjob_status(towerjobstatus,account_id):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        subject = "Tower job status for new AWS account with account id: " + account_id
        message = 'Tower jobs with their status provided below\n\n'
        for tower_job, status in towerjobstatus.items(): 
            message += tower_job + ":" + str(status) + '\n'

        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except ClientError as e:
        print("Error : {}".format(e))

def lambda_handler(event,context):

    is_job_successful = False
    towerjobs = event['tower_job_ids']
    towerjobstatus = {}
    account_id = event['account_id']

    #jobid = "257751"

    #Secrets Manager will be setup in US-East-1 within master account
    secret_name = os.environ['ServiceAccountCreds']
    region_name = os.environ['SecretsManagerRegionName']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account = response_dict['IAMServiceAccount']
    
    # Iterating over values 
    for tower_job, job_id in towerjobs.items(): 
        print(tower_job, ":", job_id) 
        # Invoke tower url to check job status
        is_job_successful = sendRequest(job_id,service_account)
        print(is_job_successful)
        towerjobstatus[tower_job] = is_job_successful
    send_towerjob_status(towerjobstatus,account_id)
    event('tower_job_status') = towerjobstatus
    print(towerjobstatus)
    return event
