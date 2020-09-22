import json
import boto3
import base64
import os
from botocore.exceptions import ClientError

def create_secret(secretname,regionname,kmskeyid,access_key_id,secret_access_key):
    is_iam_automation_user_created = False
    print(secretname)
    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname,
    )

    try:
        get_create_secret_response = client.create_secret(
            Name=secretname,
            KmsKeyId=kmskeyid,
            Description='Secret to store ' + secretname + ' credentials',
            SecretString='{"access_key_id":"' + access_key_id + '","secret_access_key":"' + secret_access_key + '"}'
        )
        print(get_create_secret_response)
        is_iam_automation_user_created = True
    except ClientError as e:
        print("Exception raised:", e)
        raise
    finally:
        return is_iam_automation_user_created

def get_account_name(account_id):

    session = boto3.session.Session()
    client = session.client(
        service_name='organizations',
        region_name='us-east-1'
    )

    try:
        get_describe_account_response = client.describe_account(
            AccountId=account_id
        )
    except ClientError as e:
        print("The request could not be completed:", e)
        raise
    else:
        return get_describe_account_response

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
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def create_account_alias(credentials,account_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        get_create_acct_alias_response = client.create_account_alias(
            AccountAlias=account_name.lower()
        )
    except ClientError as e:
        print("The request could not be completed:", e)
    else:
        return get_create_acct_alias_response

def create_iam_user(credentials,user_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        get_create_user_response = client.create_user(
            UserName=user_name
        )
    except ClientError as e:
        print("The request could not be completed:", e)
    else:
        return get_create_user_response

def attach_iam_policy(credentials,user_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        get_create_user_response = client.attach_user_policy(
            PolicyArn='arn:aws:iam::aws:policy/IAMFullAccess',
            UserName=user_name
        )
    except ClientError as e:
        print("The request could not be completed:", e)
    else:
        print(get_create_user_response)
        return get_create_user_response

def create_access_key(credentials,user_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        get_create_access_key_response = client.create_access_key(
            UserName=user_name
        )
    except ClientError as e:
        print("The request could not be completed:", e)
    else:
        print(get_create_access_key_response)
        return get_create_access_key_response

def lambda_handler(event,context):

    #Retrieve account id from State Machine event variable
    account_id = event['account_id']

    #Retrieve account name for the new account created
    response = get_account_name(account_id)
    account_name = response['Account']['Name']
    event['account_name'] = account_name
    print("account name is:" + event['account_name'])

    #Assume role of member account before creating IAM user within member account
    account_role = 'OrganizationAccountAccessRole'    
    credentials = assume_role(account_id, account_role)
    
    user_name =  os.environ['IAMUserName']
    #user_name = 'AnsibleAutomationIAM'

    #Create account alias to be used with Okta mapping
    response = create_account_alias(credentials,account_name)
    print(response)

    # Create automation IAM user within member account
    response = create_iam_user(credentials,user_name)

    response = attach_iam_policy(credentials,user_name)
    # Create secret key and access key id for the newly created user for programmatic access
    response = create_access_key(credentials,user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']

    #Secrets Manager will be setup in US-East-1 within the master account

    secret_name =  user_name + "-" + account_id
    region_name = os.environ['SecretsManagerRegionName']
    kmskeyid = os.environ['KMSKeyID']
    #region_name = 'us-east-1'

    #Create secret within Secrets Manager with the IAM Automation Account credentials    
    response = create_secret(secret_name,region_name,kmskeyid,access_key_id,secret_access_key)
    event['is_iam_automation_user_created'] = response
    return event