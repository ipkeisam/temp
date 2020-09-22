import json
import traceback
import os
import boto3
import time
from random import randint
from botocore.exceptions import ClientError
import requests

def get_secret(secretname,regionname):

    print(secretname)
    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname,
        #endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT']
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

def create_assume_policy_doc(qualysAccountId,EXTERNALID):

        policydoc = '{\n' + \
        ' "Version": "2012-10-17",\n' + \
        ' "Statement":[\n' + \
        '  {\n' + \
        '   "Effect": "Allow",\n' + \
        '   "Principal": {\n' + \
        '     "AWS": "arn:aws:iam::' + str(qualysAccountId) + ':root"\n' + \
        '    },\n' + \
        '    "Action":"sts:AssumeRole",\n' + \
        '    "Condition": {\n' + \
        '      "StringEquals": {\n' + \
        '        "sts:ExternalId": "' + str(EXTERNALID) + '"\n' + \
        '      }\n' + \
        '    }\n' + \
        '  }\n' + \
        ' ]\n' + \
        '}\n'
        print(policydoc)
        return policydoc

def attach_managed_policy(credentials,rolename,accountid):
    qualys_policy_attached = False
    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        attach_policy_response = client.attach_role_policy(
                                RoleName=rolename,
                                PolicyArn='arn:aws:iam::' + str(accountid) + ':policy/QualysPolicyForEC2Connector'
        )
        print(attach_policy_response)
        qualys_policy_attached = True
    except ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return qualys_policy_attached

def create_qualys_role(credentials,role_name,policydoc):
    qualys_role_created = False
    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


    try:
        create_role_response = client.create_role(
                                    Path='/',
                                    RoleName=role_name,
                                    AssumeRolePolicyDocument=policydoc,
                                    Description='Qualys Connect Role',
        )
        print(create_role_response)
        qualys_role_created = True
    except ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return qualys_role_created

# def getAccountAlias(credentials,account_id):
#     accountName = account_id
#     try:
#         session = boto3.session.Session()
#         client = session.client(
#             service_name='iam',
#             aws_access_key_id=credentials['AccessKeyId'],
#             aws_secret_access_key=credentials['SecretAccessKey'],
#             aws_session_token=credentials['SessionToken']
#         )
#         paginator = client.get_paginator('list_account_aliases')
#         for response in paginator.paginate():
#             if 'AccountAliases' in response:
#                 print(response['AccountAliases'])
#                 print(type(response['AccountAliases'][0]))
#                 accountName = str(response['AccountAliases'][0])
#                 break
#             else:
#                 accountName = account_id
#     except Exception as e:
#         print("The request could not be completed:", e)
#         raise
#     finally:
#         return accountName

def lambda_handler(event,context):
    #EXTERNALID = os.environ['EXTERNALID']
    ROLENAME = os.environ['ROLENAME']
    BASEURL = os.environ['BASEURL']
    dataConnectorId = 12345678
    qualysAccountId = 12345

    #Secrets Manager will be setup in US-East-1 within master account
    secret_name =  os.environ['QUALYSSECRETNAME']
    region_name = os.environ['SMREGIONNAME']

    #Retrieve account id and account name from State Machine event variable
    ACCOUNT_ID = event['account_id']
    accountName = event['account_name']

    #Retrieve user name and password from Secrets Manager
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    username = response_dict['user_name']
    password = response_dict['password']

    #Assume role of member account before creating Qualys IAM role within member account
    account_role = 'OrganizationAccountAccessRole'    
    credentials = assume_role(ACCOUNT_ID, account_role)

    try:
        api_endpoint="{}/qps/rest/2.0/create/am/awsassetdataconnector".format(BASEURL)
        EXTERNALID = randint(1000000000000000000,999999999999999999999999999999999)
        data= {
            "ServiceRequest":{
                "data":{
                    "AwsAssetDataConnector":{
                        "name":"CG EC2 {0}".format(accountName.upper()),
                        "description": "Account Name: {0} - Connector for AWS Account {1}".format(accountName.upper(), ACCOUNT_ID),
                        "arn":"arn:aws:iam::{}:role/{}".format(ACCOUNT_ID, ROLENAME),
                        "externalId":"{}".format(EXTERNALID),
                        "endpoints":
                        {
                            "add":
                            {
                                "AwsEndpointSimple": [
                                {
                                    "regionCode": "us-west-1"
                                },               
                                {
                                    "regionCode": "us-west-2"
                                },
                                {
                                    "regionCode": "us-east-1"
                                },
                                {
                                    "regionCode": "us-east-2"
                                },               
                                {
                                    "regionCode": "ap-northeast-2"
                                },
                                {
                                    "regionCode": "ap-northeast-1"
                                },
                                {
                                    "regionCode": "ap-southeast-1"
                                },               
                                {
                                    "regionCode": "ap-southeast-2"
                                },
                                {
                                    "regionCode": "eu-west-1"
                                },
                                {
                                    "regionCode": "eu-west-2"
                                },               
                                {
                                    "regionCode": "eu-west-3"
                                },
                                {
                                    "regionCode": "ap-south-1"
                                },               
                                {
                                    "regionCode": "ca-central-1"
                                },
                                {
                                    "regionCode": "eu-central-1"
                                },
                                {
                                    "regionCode": "sa-east-1"
                                }
                                ]
                            }
                        },
                        "disabled":"false",
                        "useForCloudView":"false",
                        "activation": {
                            "set": {
                            "ActivationModule": [
                                "VM"
                                ]
                            }
                        }
                    }
                }
            }
        }
        auth=(username, password)
        print("DATA: {}".format(data))
        # print("AUTH: {}".format(auth))
        headers = {"X-Requested-With": "Qualys Lambda (python)"}
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
        r = requests.post(api_endpoint, json=data, auth=auth, headers=headers)
        print("RESPONSE: {}".format(r))
        data = r.json()
        print("DATA: {}".format(data))
        responseData = {}
        responseData['qualys_connector_created'] = False
        if 'ServiceResponse' in data:
            if 'responseCode' in data['ServiceResponse']:
                responseData['responseCode'] = data['ServiceResponse']['responseCode']
            if 'responseErrorDetails' in data['ServiceResponse']:
                responseData['responseErrorDetails'] = data['ServiceResponse']['responseErrorDetails']['errorMessage']
                event['QualysOutput'] = responseData
                return event
            if 'data' in data['ServiceResponse']:
                if 'AwsAssetDataConnector' in data['ServiceResponse']['data'][0]:
                    record = data['ServiceResponse']['data'][0]['AwsAssetDataConnector']
                    if 'id' in record:
                        dataConnectorId = record['id']
                    if 'qualysAwsAccountId' in record:
                        qualysAccountId = record['qualysAwsAccountId']
                responseData['qualys_connector_created'] = True
                
        #Create assume policy doc to be attached to the Qualys role
        policydoc = create_assume_policy_doc(qualysAccountId,EXTERNALID)
    
        #Create Qualys role within member account
        create_role_response = create_qualys_role(credentials,ROLENAME,policydoc)
        responseData['qualys_role_created'] = create_role_response
    
        #Attached SecurityAudit managed polciy to the created Qualys role
        attach_policy_response = attach_managed_policy(credentials,ROLENAME,ACCOUNT_ID)
        responseData['qualys_policy_attached'] = attach_policy_response
    
        event['QualysOutput'] = responseData
    except Exception as e:
        responseData = {}
        responseData['qualys_connector_created'] = False
        traceback.print_exc()
        responseData['responseErrorDetails'] = e
        event['QualysOutput'] = responseData
        raise
    finally:
        return event