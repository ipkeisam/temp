from __future__ import print_function
import boto3
import botocore
import time

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

def put_public_access_block(credentials,accountid):
    is_s3_public_access_blocked = False
    session = boto3.session.Session()
    # Create S3Control client
    s3control_client = session.client(
        service_name='s3control',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        # Block public access
        response = s3control_client.put_public_access_block(
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            },
            AccountId=accountid
        )
        is_s3_public_access_blocked = True
    except botocore.exceptions.ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return is_s3_public_access_blocked
        
def lambda_handler(event,context):
    
    account_id = event['account_id']
    account_role = 'OrganizationAccountAccessRole'

    #Assume role of member account
    credentials = assume_role(account_id, account_role)

    is_s3_public_access_blocked = put_public_access_block(credentials,account_id)
    event['is_s3_public_access_blocked'] = is_s3_public_access_blocked
  
    return event