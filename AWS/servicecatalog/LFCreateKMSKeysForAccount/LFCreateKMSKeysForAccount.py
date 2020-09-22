from __future__ import print_function
import boto3
import botocore
import argparse
import os
import urllib
import json
import requests
import base64
import time

def sendTriggerLambdaResponse(event, context, responseStatus, responseData):
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}
    print('RESPONSE BODY:n' + json.dumps(responseBody))
    try:
        req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return
    except requests.exceptions.RequestException as e:
        print(e)
        raise

def get_secret(secretname,regionname):

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname
        #endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT']
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretname
        )
    except botocore.exceptions.ClientError as e:
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

def getOktaToken(serviceaccount):

    # KMS API url authenticated using Okta token
    url = os.environ['KMSOktaURL']

    payload = {}
    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'authorization': "Basic " + serviceaccount,
        'accept': "application/json"
    }

    response = requests.post(url, headers=headers)
    data = json.loads(response.text)
    print(str(data['access_token']))
    print(response.text)
    return str(data['access_token'])

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

def createPolicyForS3(account_id,deployregion):

        s3service = "s3." + deployregion + ".amazonaws.com"
        keypolicy = '{\n' + \
        ' "Version": "2012-10-17",\n' + \
        ' "Id": "key-default-s3",\n' + \
        ' "Statement": [\n' + \
        '    {\n' + \
        '        "Sid": "Enable IAM User Permissions",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "arn:aws:iam::' + account_id + ':root"\n' + \
        '        },\n' + \
        '        "Action": "kms:*",\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow access for Key Administrators",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": [\n' + \
        '               "arn:aws:iam::' + account_id + ':role/SysAdmin",\n' + \
        '               "arn:aws:iam::' + account_id + ':user/KeyMgmt_01",\n' + \
        '               "arn:aws:iam::' + account_id + ':role/EncryptionKeyMgmtAdmin"\n' + \
        '           ]\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Create*",\n' + \
        '            "kms:Describe*",\n' + \
        '            "kms:Enable*",\n' + \
        '            "kms:List*",\n' + \
        '            "kms:Put*",\n' + \
        '            "kms:Update*",\n' + \
        '            "kms:Revoke*",\n' + \
        '            "kms:Disable*",\n' + \
        '            "kms:Get*",\n' + \
        '            "kms:Delete*",\n' + \
        '            "kms:ImportKeyMaterial",\n' + \
        '            "kms:TagResource",\n' + \
        '            "kms:UntagResource",\n' + \
        '            "kms:ScheduleKeyDeletion",\n' + \
        '            "kms:CancelKeyDeletion"\n' + \
        '        ],\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow use of the key",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Encrypt",\n' + \
        '            "kms:Decrypt",\n' + \
        '            "kms:ReEncrypt*",\n' + \
        '            "kms:GenerateDataKey*",\n' + \
        '            "kms:DescribeKey"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + s3service + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow attachment of persistent resources",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:CreateGrant",\n' + \
        '            "kms:ListGrants",\n' + \
        '            "kms:RevokeGrant"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "Bool": {\n' + \
        '                "kms:GrantIsForAWSResource": "true"\n' + \
        '            },\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + s3service + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    }\n' + \
        ' ]\n' + \
        '}'

        #print(keypolicy)
        return keypolicy

def createPolicyForRDS(account_id,deployregion):

        rdsservice = "rds." + deployregion + ".amazonaws.com"
        dynamodbservice = "dynamodb." + deployregion + ".amazonaws.com"
        keypolicy = '{\n' + \
        ' "Version": "2012-10-17",\n' + \
        ' "Id": "key-default-rds",\n' + \
        ' "Statement": [\n' + \
        '    {\n' + \
        '        "Sid": "Enable IAM User Permissions",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "arn:aws:iam::' + account_id + ':root"\n' + \
        '        },\n' + \
        '        "Action": "kms:*",\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow access for Key Administrators",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": [\n' + \
        '               "arn:aws:iam::' + account_id + ':role/SysAdmin",\n' + \
        '               "arn:aws:iam::' + account_id + ':user/KeyMgmt_01",\n' + \
        '               "arn:aws:iam::' + account_id + ':role/EncryptionKeyMgmtAdmin"\n' + \
        '           ]\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Create*",\n' + \
        '            "kms:Describe*",\n' + \
        '            "kms:Enable*",\n' + \
        '            "kms:List*",\n' + \
        '            "kms:Put*",\n' + \
        '            "kms:Update*",\n' + \
        '            "kms:Revoke*",\n' + \
        '            "kms:Disable*",\n' + \
        '            "kms:Get*",\n' + \
        '            "kms:Delete*",\n' + \
        '            "kms:ImportKeyMaterial",\n' + \
        '            "kms:TagResource",\n' + \
        '            "kms:UntagResource",\n' + \
        '            "kms:ScheduleKeyDeletion",\n' + \
        '            "kms:CancelKeyDeletion"\n' + \
        '        ],\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow use of the key",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Encrypt",\n' + \
        '            "kms:Decrypt",\n' + \
        '            "kms:ReEncrypt*",\n' + \
        '            "kms:GenerateDataKey*",\n' + \
        '            "kms:DescribeKey"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + rdsservice + '",\n' + \
        '                   "' + dynamodbservice + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow attachment of persistent resources",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:CreateGrant",\n' + \
        '            "kms:ListGrants",\n' + \
        '            "kms:RevokeGrant"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "Bool": {\n' + \
        '                "kms:GrantIsForAWSResource": "true"\n' + \
        '            },\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + rdsservice + '",\n' + \
        '                   "' + dynamodbservice + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    }\n' + \
        ' ]\n' + \
        '}'

        #print(keypolicy)
        return keypolicy

def createPolicyForVol(account_id,deployregion):

        ec2service = "ec2." + deployregion + ".amazonaws.com"
        efsservice = "elasticfilesystem." + deployregion + ".amazonaws.com"
        keypolicy = '{\n' + \
        ' "Version": "2012-10-17",\n' + \
        ' "Id": "key-default-vol",\n' + \
        ' "Statement": [\n' + \
        '    {\n' + \
        '        "Sid": "Enable IAM User Permissions",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "arn:aws:iam::' + account_id + ':root"\n' + \
        '        },\n' + \
        '        "Action": "kms:*",\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow access for Key Administrators",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": [\n' + \
        '               "arn:aws:iam::' + account_id + ':role/SysAdmin",\n' + \
        '               "arn:aws:iam::' + account_id + ':user/KeyMgmt_01",\n' + \
        '               "arn:aws:iam::' + account_id + ':role/EncryptionKeyMgmtAdmin"\n' + \
        '           ]\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Create*",\n' + \
        '            "kms:Describe*",\n' + \
        '            "kms:Enable*",\n' + \
        '            "kms:List*",\n' + \
        '            "kms:Put*",\n' + \
        '            "kms:Update*",\n' + \
        '            "kms:Revoke*",\n' + \
        '            "kms:Disable*",\n' + \
        '            "kms:Get*",\n' + \
        '            "kms:Delete*",\n' + \
        '            "kms:ImportKeyMaterial",\n' + \
        '            "kms:TagResource",\n' + \
        '            "kms:UntagResource",\n' + \
        '            "kms:ScheduleKeyDeletion",\n' + \
        '            "kms:CancelKeyDeletion"\n' + \
        '        ],\n' + \
        '        "Resource": "*"\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow use of the key",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Encrypt",\n' + \
        '            "kms:Decrypt",\n' + \
        '            "kms:ReEncrypt*",\n' + \
        '            "kms:GenerateDataKey*",\n' + \
        '            "kms:DescribeKey"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + ec2service + '",\n' + \
        '                   "' + efsservice + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow attachment of persistent resources",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:CreateGrant",\n' + \
        '            "kms:ListGrants",\n' + \
        '            "kms:RevokeGrant"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "Bool": {\n' + \
        '                "kms:GrantIsForAWSResource": "true"\n' + \
        '            },\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + ec2service + '",\n' + \
        '                   "' + efsservice + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    }\n' + \
        ' ]\n' + \
        '}'

        #print(keypolicy)
        return keypolicy

def create_cmk(credentials,desc,policy,environment,deployregion):
    """Create a KMS Customer Master Key

    The created CMK is a Customer-managed key stored in AWS KMS.

    :param desc: key description
    :return Tuple(KeyId, KeyArn) where:
        KeyId: AWS globally-unique string ID
        KeyArn: Amazon Resource Name of the CMK
    :return Tuple(None, None) if error
    """
    is_cmk_created = False
    keyid = ''
    keyarn = ''
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                #endpoint_url=os.environ['KMS_ENDPOINT']
            )
    try:
        # Create CMK
        response = kms_client.create_key(
            Policy=policy,
            Description=desc,
            KeyUsage='ENCRYPT_DECRYPT',
            CustomerMasterKeySpec='SYMMETRIC_DEFAULT',
            Origin='EXTERNAL',
            Tags=[
                {
                    'TagKey': 'cost-center',
                    'TagValue': '524154'
                },
                {
                    'TagKey': 'env-type',
                    'TagValue': environment
                },
                {
                    'TagKey': 'exp-date',
                    'TagValue': '99-00-9999'
                },
                {
                    'TagKey': 'ppmc-id',
                    'TagValue': '69058'
                },
                {
                    'TagKey': 'sd-period',
                    'TagValue': 'na'
                },
                {
                    'TagKey': 'toc',
                    'TagValue': 'ETOC'
                },
                {
                    'TagKey': 'usage-id',
                    'TagValue': 'BB00000008'
                },
            ]
        )
        is_cmk_created = True
        keyid = response['KeyMetadata']['KeyId']
        keyarn = response['KeyMetadata']['Arn']
    except botocore.exceptions.ClientError as e:
        print(e)
        raise
    finally:
        # Return the key ID and ARN
        return keyid, keyarn, is_cmk_created

def get_importtoken_and_wrappingkey(credentials,keyid,deployregion):

    extract_token_and_key_successful = False
    import_token = ''
    wrapping_key = ''
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                #endpoint_url=os.environ['KMS_ENDPOINT']
            )
    try:
        response = kms_client.get_parameters_for_import(
            KeyId=keyid,
            WrappingAlgorithm='RSAES_OAEP_SHA_1',
            WrappingKeySpec='RSA_2048'
        )
        import_token = base64.b64encode(response['ImportToken'])
        wrapping_key = base64.b64encode(response['PublicKey'])
        extract_token_and_key_successful = True
    except botocore.exceptions.ClientError as e:
        print("Error extracting import token and/or wrapping key. Error : {}".format(e))
        raise
    finally:
        # Return the import token and wrapping key
        return import_token, wrapping_key,extract_token_and_key_successful

def encrypt_key(keyid,wrapping_key,okta_token,environment):
    is_encrypt_key_successful = False
    url = os.environ['KMS_URL']

    #Manipulate wrapping_key to be passed as a string without the binary attached
    str_wrapping_key = str(wrapping_key)
    stripped_wrapping_key = str_wrapping_key.strip("b'")
    final_stripped_wrapping_key = stripped_wrapping_key.strip("'")

    payload = {
        "name": keyid,
        "type": "aws",
        "atmId": "BB00000008",
        "env": environment,
        "wrappingKey": final_stripped_wrapping_key
    } 

    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + okta_token
    }

    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    response_status = response.status_code
    if '201' in str(response_status):
        is_encrypt_key_successful = True
    return response,is_encrypt_key_successful

def import_key_material(credentials,keyid,importtoken_en,encryptedkeymaterial_en,deployregion):
    import_key_material_successful = False
    response_status = ''
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                #endpoint_url=os.environ['KMS_ENDPOINT']
            )
    importtoken_binary = base64.b64decode(importtoken_en)
    encryptedkeymaterial_binary = base64.b64decode(encryptedkeymaterial_en)
    try:    
        response = kms_client.import_key_material(
            KeyId=keyid,
            ImportToken=importtoken_binary,
            EncryptedKeyMaterial=encryptedkeymaterial_binary,
            ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE'
        ) 
        print(response['ResponseMetadata']['HTTPStatusCode'])
        if '200' in str(response['ResponseMetadata']['HTTPStatusCode']):
            import_key_material_successful = True
    except botocore.exceptions.ClientError as e:
        print("Error importing key material. Error : {}".format(e))
        raise
    finally:
        return import_key_material_successful

def create_key_alias(credentials,keyid,keyalias,deployregion):

    response = ''
    create_key_alias_successful = False
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                #endpoint_url=os.environ['KMS_ENDPOINT']
            )
    try:
        response = kms_client.create_alias(
            AliasName=keyalias,
            TargetKeyId=keyid
        )
        print(response)
        create_key_alias_successful = True
    except botocore.exceptions.ClientError as e:
        print("Error creating key alias. Error : {}".format(e))
        raise
    finally:
        return response,create_key_alias_successful

def set_default_ebs_encryption(credentials,keyid,deployregion):

    response = ''
    default_ebs_encryption_successful = False
    session = boto3.session.Session()
    ec2_client = session.client(
                service_name='ec2',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                #endpoint_url=os.environ['EC2_ENDPOINT']
            )
    try:
        response = ec2_client.modify_ebs_default_kms_key_id(
            KmsKeyId=keyid,
            DryRun=False
        )
        print(response)
        print(response['ResponseMetadata']['HTTPStatusCode'])
        if '200' in str(response['ResponseMetadata']['HTTPStatusCode']):
            response = ec2_client.enable_ebs_encryption_by_default(
                DryRun=False
            )
            print(response)
            if response['EbsEncryptionByDefault']:
                default_ebs_encryption_successful = True
    except Exception as e:
        print("Error setting default ebs encryption. Error : {}".format(e))
        raise
    finally:
        print(default_ebs_encryption_successful)
        return default_ebs_encryption_successful

def lambda_handler(event,context):
    
    responseStatus = 'FAILED'
    are_kms_keys_created = {}
    default_ebs_encryption_successful = {}
    print(event)
    environment = event['ResourceProperties']['environment_type'].lower()
    account_name = event['ResourceProperties']['account_name'].lower()
    account_id = event['ResourceProperties']['account_id']
    kms_resources = event['ResourceProperties']['kms_resources']
    kms_regions = event['ResourceProperties']['kms_regions']

    kmsresources = kms_resources.split(",")
    kmsregions = kms_regions.split(",")

    environment_mapping = {'lab':'oz-dev', 'ftdev':'oz-dev', 'na':'oz-dev', 'foundation':'az-inf', 'sbx':'oz-inf', 'dev':'oz-dev', 'qa':'snp-atn', 'prd':'cpz-prd'}

    #Secrets Manager will be setup in US-East-1 within master account
    secretname =  os.environ['KMSServiceAccountCreds']
    regionname = os.environ['SecretsManagerRegionName']

    #Get the service account to be used to invoke KMS web service
    response = get_secret(secretname,regionname)
    response_dict = json.loads(response)
    service_account = response_dict['OktaServiceAccount']

    #Get Okta token to be used to make HSM call
    oktatoken = getOktaToken(service_account)

    #Assume role of member account before creating Qualys IAM role within member account
    account_role = 'OrganizationAccountAccessRole'    
    credentials = assume_role(account_id, account_role)

    keydescription = ""
    length = len(kmsresources)
    for i in range(length):
        resource = kmsresources[i]
        print(resource)

        #iterate through all defined kmsregions to deploy the keys
        for deployregion in kmsregions:
        #Create key policy for the specific resource
            keypolicy = ''
            if "vol" in resource:
                keydescription = "default KMS for ebs and efs" 
                keypolicy = createPolicyForVol(account_id,deployregion)
            elif "rds" in resource:
                keydescription = "default KMS for rds"
                keypolicy = createPolicyForRDS(account_id,deployregion)
            else:
                keydescription = "default KMS for s3"
                keypolicy = createPolicyForS3(account_id,deployregion)
            print(keypolicy)
            key_alias_region = deployregion.replace('-', '')
            keyalias = "alias/{0}/{1}/{2}/0/kek".format(account_name,key_alias_region,resource)
            #Create CMK
            (keyid,keyarn,is_cmk_created) = create_cmk(credentials,keydescription,keypolicy,environment,deployregion)
            print("Key id:"+ str(keyid))
            print("Key arn:"+ str(keyarn))
            keyalias = "alias/{0}/{1}/{2}/0/kek".format(account_name,key_alias_region,resource)
            time.sleep(5)
            are_kms_keys_created[keyalias] = False
            if is_cmk_created:
                #Obtain import token and wrapping key
                (importtoken,wrapping_key,extract_token_and_key_successful) = get_importtoken_and_wrappingkey(credentials,keyid,deployregion)
                time.sleep(5)
                if extract_token_and_key_successful:
                    print(importtoken)
                    print(wrapping_key)

                    #Encrypt key material and obtain wrapper key to be imported
                    (wrappedkey_json,is_encrypt_key_successful) = encrypt_key(keyid,wrapping_key,oktatoken,environment_mapping[environment])
                    time.sleep(5)
                    if is_encrypt_key_successful:
                        data = json.loads(wrappedkey_json.text)
                        wrappedkey = data['wrappedKey']

                        #Import wrapped key into the original key created for the resource
                        import_key_material_successful = import_key_material(credentials,keyid,importtoken,wrappedkey,deployregion)
                        time.sleep(5)
                        if import_key_material_successful:
                            #Create key alias
                            (response,create_key_alias_successful) = create_key_alias(credentials,keyid,keyalias,deployregion)
                            time.sleep(5)
                            if create_key_alias_successful:
                                are_kms_keys_created[keyalias] = True
                                if 'vol' in keyalias:
                                    default_ebs_encryption_successful[deployregion] = set_default_ebs_encryption(credentials,keyid,deployregion)

    print(are_kms_keys_created)
    print(default_ebs_encryption_successful)
    responseStatus = 'SUCCESS'
    sendTriggerLambdaResponse(event, context, responseStatus, are_kms_keys_created)