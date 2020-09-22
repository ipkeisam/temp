import requests
import json
import boto3
import base64
import os
from botocore.exceptions import ClientError

def sendRequest(ad_group,role,tower_env,account_id,service_account):
    is_iam_va_playbook_invoked = False
    url = os.environ['ANSIBLE_TOWER_URL']
    job_id = ''
    payload = {
        "extra_vars":{
            "account_number":account_id,
            "ad_group":ad_group,
            "role":role,
            "tower_env":tower_env
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    if '201' in str(response.status_code):
        is_iam_va_playbook_invoked = True
        json_response_dict = json.loads(response.text)
        job_id = json_response_dict['id']
    print(response.status_code)
    return is_iam_va_playbook_invoked,job_id

def sendDeveloperRequest(user_initials,role,tower_env,account_id,service_account):
    is_iam_va_playbook_invoked = False
    url = os.environ['DEVELOPER_ANSIBLE_TOWER_URL']

    payload = {
        "extra_vars":{
            "account_number":account_id,
            "user_initials":user_initials,
            "role":role,
            "tower_env":tower_env
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    if '201' in str(response.status_code):
        is_iam_va_playbook_invoked = True
        json_response_dict = json.loads(response.text)
        job_id = json_response_dict['id']
    print(response.status_code)
    return is_iam_va_playbook_invoked,job_id

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

    is_iam_va_playbook_invoked = {}
    tower_job_ids = {}

    #Check environment and capture appropriate ITAM env type
    environment = event['environment_type'].lower()

    #Check if this is a developer account
    user_initials = event['user_initials']

    secret_name = os.environ['IAMServiceAccountCreds']
    region_name = os.environ['SecretsManagerRegionName']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account_IAM = response_dict['IAMServiceAccount']

    is_iam_va_playbook_invoked['read_access_role'] = False
    is_iam_va_playbook_invoked['broad_access_role'] = False

    if user_initials == "na":
        qa_environment_default = "SNP_ATN"
        if environment == "qa":
            qadatatype = event['qadatatype']
            if qadatatype == "sensitive":
                qa_environment_default = "SNP_ATS"

        environment_mapping = {'na':'na', 'foundation':'na', 'sbx':'OZ_DEV', 'dev':'OZ_DEV', 'qa':qa_environment_default, 'prd':'CPZ_PRD'}

        if environment_mapping[environment] != "na":
            
            #Extract event variables
            usageid = event['usageid']
            account_id = event['account_id']
            tower_env = event['organization_unit_name']

            #Obtain environment variable to be passed as part of the payload
            broadaccessrole = os.environ['BroadAccessVerticalRoleMapping']
            readaccessrole = os.environ['ReadAccessVerticalRoleMapping']

            #set AD group to be passed to payload (format <environment_mapping[environment]>_<usage_id>_Admin)
            ad_braodaccess_group = environment_mapping[environment] + "_" + usageid + "_Admin"

            # Invoke tower url for broad access role
            (is_iam_va_playbook_invoked['broad_access_role'],job_id) = sendRequest(ad_braodaccess_group,broadaccessrole,tower_env,account_id,service_account_IAM)
            print(is_iam_va_playbook_invoked)
            print(job_id)
            tower_job_ids['IAM Vertical Access (Broad Access Role) Playbook Execution Status'] = job_id
                    
            #set AD group to be passed to payload (format <environment_mapping[environment]>_<usage_id>_Admin for DEV/SBX and <environment_mapping[environment]>_<usage_id>_Role_BEAppUsers for rest)
            if (environment == "sbx") or (environment == "dev"):
                ad_readaccess_group = environment_mapping[environment] + "_" + usageid + "_Admin"
            else:
                ad_readaccess_group = environment_mapping[environment] + "_" + usageid + "_Role_BEAppUsers"

            # Invoke tower url for read access role
            (is_iam_va_playbook_invoked['read_access_role'],job_id) = sendRequest(ad_readaccess_group,readaccessrole,tower_env,account_id,service_account_IAM)
            print(is_iam_va_playbook_invoked)
            print(job_id)
            tower_job_ids['IAM Vertical Access (Broad Read Role) Playbook Execution Status'] = job_id
    else:
        #Obtain environment variable to be passed as part of the payload
        broadaccessrole = os.environ['BroadAccessVerticalRoleMapping']

        #Extract event variables
        account_id = event['account_id']
        tower_env = event['organization_unit_name']

        #Invoke the tower job associated with developer access to AWS account
        (is_iam_va_playbook_invoked['broad_access_role'],job_id) = sendDeveloperRequest(user_initials,broadaccessrole,tower_env,account_id,service_account_IAM)
        print(is_iam_va_playbook_invoked)
        print(job_id)
        tower_job_ids['IAM Vertical Access (Broad Access Role) Playbook Execution Status'] = job_id

    event['tower_job_ids'] = tower_job_ids
    event['is_iam_va_playbook_invoked'] = is_iam_va_playbook_invoked
    return event