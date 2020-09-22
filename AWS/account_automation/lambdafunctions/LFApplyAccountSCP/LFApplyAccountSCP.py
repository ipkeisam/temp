from __future__ import print_function
import boto3
import botocore
import os
import time

def get_client(service):
    client = boto3.client(service)
    return client

def attach_SCP(account_id,scps):
    is_scp_setup_complete = False
    client = get_client('organizations')
    try:
        if scps is not None:
            scp_list = scps.split(",")
            for scp in scp_list:
                attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=account_id)
                print("Attach policy response "+str(attach_policy_response))
            is_scp_setup_complete = True
    except Exception as ex:
        print(ex)
        raise
    finally:
        return is_scp_setup_complete

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

def update_account_password_policy(credentials):
    is_password_policy_setup_complete = False
    session = boto3.session.Session()
    #Create IAM client
    iam_client = session.client(
        service_name='iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        response = iam_client.update_account_password_policy(
            MinimumPasswordLength=15,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
            HardExpiry=False
        )
        is_password_policy_setup_complete = True
    except Exception as ex:
        print(ex)
        raise
    finally:
        return is_password_policy_setup_complete


def lambda_handler(event,context):

    scps = os.environ['SCPs']
    event['is_scp_setup_complete'] = False

    account_id = event['account_id']
    print("Account Id:" + account_id)

    if scps is not None:
        attach_SCP_response = attach_SCP(account_id,scps)
        event['is_scp_setup_complete'] = attach_SCP_response

    account_role = 'OrganizationAccountAccessRole'
    #Assume role of new account to update the account password policy
    credentials = assume_role(account_id, account_role)

    #Update password policy for IAM users within an account
    update_password_policy_response = update_account_password_policy(credentials)
    event['is_password_policy_setup_complete'] = update_password_policy_response

    return event