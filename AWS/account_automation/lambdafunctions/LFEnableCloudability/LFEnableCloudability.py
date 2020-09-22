import json
import boto3
import base64
import os
import time
from botocore.exceptions import ClientError
import requests

def getCFTemplate(cdapikey,account_id):

    url = "https://api.cloudability.com/v3/vendors/AWS/accounts/" + account_id + "/cloudformation-template"

    headers = {
        'Authorization': "Basic " + cdapikey
    }

    response = requests.get(url, headers=headers)
    json_data = json.loads(response.text)
    
    print(json_data)
    return json_data
    
def createCredentials(cdapikey,account_id):
    check_account_verification = True
    account_verified = False
    url = "https://api.cloudability.com/v3/vendors/aws/accounts"

    payload = {
      "vendorAccountId": account_id,
      "type": "aws_role"
    } 

    headers = {
        'Content-Type': "application/json",
        'Authorization': "Basic " + cdapikey
    }

    counter = 30
    while check_account_verification is True:
        counter -=1
        check_account_verification = False
        response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
        json_data = json.loads(response.text)
        print(json_data)
        if counter > 0:
            if 'error' in json_data:
                check_account_verification = True
                time.sleep(10)
            else:
                account_verified = True
                break
        else:
            break
    
    return (json_data,account_verified)
    
def verifyAccount(cdapikey,account_id):

    url = "https://api.cloudability.com/v3/vendors/AWS/accounts/" + account_id + "/verification"

    headers = {
        'Authorization': "Basic " + cdapikey
    }

    response = requests.post(url, headers=headers)
    json_data = json.loads(response.text)
    print(json_data)

    return json_data

def get_secret(secretname,regionname):

    print(secretname)
    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretname
        )
    except ClientError as e:
        print("Exception raised:", e)
    else:
        #Secrets Manager decrypts the secret value using the associated KMS CMK
        #Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret

def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def deploy_cloudability(credentials, template, stackname, stackregion, account_id):
    is_cloudability_stack_created = False
    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=stackregion)
    print("Creating stack " + stackname + " in " + account_id)
    creating_stack = True
    try:
        while creating_stack is True:
            try:
                creating_stack = False
                create_stack_response = client.create_stack(
                    StackName=stackname,
                    TemplateBody=template,
                    NotificationARNs=[],
                    Capabilities=[
                        'CAPABILITY_NAMED_IAM',
                    ],
                    OnFailure='ROLLBACK'
                )
            except ClientError as e:
                creating_stack = True
                print(e)
                print("Retrying...")
                time.sleep(10)

        stack_building = True
        print("Stack creation in process...")
        print(create_stack_response)
        while stack_building is True:
            event_list = client.describe_stack_events(StackName=stackname).get("StackEvents")
            stack_event = event_list[0]

            if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
            stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
                stack_building = False
                print("Stack construction complete.")
                is_cloudability_stack_created = True
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)
        return is_cloudability_stack_created
    except ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_cloudability_stack_created

def checkResponse(response):
    is_response_okay = True
    try:
        if response['error']:
            return is_response_okay
        return is_response_okay
    except ClientError as e:
        print("Error : {}".format(e))
        return is_response_okay

def lambda_handler(event,context):

    is_cloudability_stack_created = False

    master_account_id = os.environ['MasterAccountID']
    account_id = event['account_id']
    account_role = 'OrganizationAccountAccessRole'

    #Secrets Manager will be setup in US-East-1 within master account
    secret_name =  os.environ['CloudabilitySecret']
    region_name = os.environ['SecretsManagerRegionName']

    # retrieve Secret for Cloudability from AWS Secrets Manager
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    cdapikey = response_dict['api_key']

    if cdapikey:
        # Invoke cloudability url to verify master account (this will refresh all accounts)
        response_dict = verifyAccount(cdapikey,master_account_id)
        verification_status = response_dict['result']['verification']['state']
        print(verification_status)

        if verification_status == 'verified':
            
            #Create credentials for the member account
            (response,account_verified) = createCredentials(cdapikey,account_id)

            if account_verified:
                #Get cloudability template to be deployed in the new account
                template = getCFTemplate(cdapikey,account_id)

                if response:
                    cloudabilityStackName = 'Cloudability'
                    deployregion = 'us-east-1'

                    # Obtain credentials for the new member account
                    credentials = assume_role(account_id, account_role)

                    #Deploy the template obtained from Cloudability to the new account
                    is_cloudability_stack_created = deploy_cloudability(credentials, str(template), cloudabilityStackName, deployregion, account_id)
                    event['is_cloudability_stack_created'] = is_cloudability_stack_created
                    if is_cloudability_stack_created:

                        #Once the template is deployed successfully run a verification of the new account with Cloudability
                        response_dict = verifyAccount(cdapikey,account_id)
                        verification_status = response_dict['result']['verification']['state']
                        print(verification_status)
                    return event
            
    event['is_cloudability_stack_created'] = is_cloudability_stack_created
    return event