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
from random import randint

def sendWaitHandleResponse(wait_url, context, responseStatus, responseData):
    responseBody = {'Status': responseStatus,
                    "Reason" : "Processed",
                    'UniqueId' : "ID" + str(randint(1000000000000000000,999999999999999999999999999999999)),
                    'Data': json.dumps(responseData)}
    print('RESPONSE BODY:n' + json.dumps(responseBody))
    try:
        req = requests.put(wait_url, data=json.dumps(responseBody))
        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to wait handle.')
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

def createPolicyForSM(account_id,deployregion):

        smservice = "secretsmanager." + deployregion + ".amazonaws.com"
        lambdaservice = "lambda." + deployregion + ".amazonaws.com"
        keypolicy = '{\n' + \
        ' "Version": "2012-10-17",\n' + \
        ' "Id": "key-default-secretsmanager",\n' + \
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
        '                   "' + smservice + '",\n' + \
        '                   "' + lambdaservice + '"\n' + \
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
        '                   "' + smservice + '",\n' + \
        '                   "' + lambdaservice + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow all principals within the account to describe and list key information",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Describe*",\n' + \
        '            "kms:List*"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '         }\n' + \
        '    }\n' + \
        ' ]\n' + \
        '}'

        #print(keypolicy)
        return keypolicy

def createPolicyForShared(account_id,deployregion):

        rdsservice = "rds." + deployregion + ".amazonaws.com"
        ec2service = "ec2." + deployregion + ".amazonaws.com"
        efsservice = "elasticfilesystem." + deployregion + ".amazonaws.com"
        s3service = "s3." + deployregion + ".amazonaws.com"
        dynamodbservice = "dynamodb." + deployregion + ".amazonaws.com"
        smservice = "secretsmanager." + deployregion + ".amazonaws.com"

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
        '            "StringNotEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + rdsservice + '",\n' + \
        '                   "' + dynamodbservice + '",\n' + \
        '                   "' + s3service + '",\n' + \
        '                   "' + smservice + '",\n' + \
        '                   "' + efsservice + '",\n' + \
        '                   "' + ec2service + '"\n' + \
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
        '            "StringNotEquals": {\n' + \
        '                "kms:ViaService":[\n' + \
        '                   "' + rdsservice + '",\n' + \
        '                   "' + dynamodbservice + '",\n' + \
        '                   "' + s3service + '",\n' + \
        '                   "' + smservice + '",\n' + \
        '                   "' + efsservice + '",\n' + \
        '                   "' + ec2service + '"\n' + \
        '                 ],\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '        }\n' + \
        '    },\n' + \
        '    {\n' + \
        '        "Sid": "Allow all principals within the account to describe and list key information",\n' + \
        '        "Effect": "Allow",\n' + \
        '        "Principal": {\n' + \
        '            "AWS": "*"\n' + \
        '        },\n' + \
        '        "Action": [\n' + \
        '            "kms:Describe*",\n' + \
        '            "kms:List*"\n' + \
        '        ],\n' + \
        '        "Resource": "*",\n' + \
        '        "Condition": {\n' + \
        '            "StringEquals": {\n' + \
        '                "kms:CallerAccount": "' + account_id + '"\n' + \
        '            }\n' + \
        '         }\n' + \
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

def getSQSMessage():

    response = ''
    sqsurl =  os.environ['SQSURL']
    rgionname = os.environ['SQSRegionName']
    message_extraction_successful = False
    messages = ''
    session = boto3.session.Session()
    sqs_client = session.client(
                service_name='sqs',
                region_name=rgionname
            )
    try:
        response = sqs_client.receive_message(
            QueueUrl=sqsurl,
            MaxNumberOfMessages=1,
        )
        if response['Messages']:
            messages = response['Messages']
            print(messages)
            message_extraction_successful = True
    except Exception as e:
        print("Error retrieving messages. Error : {}".format(e))
    finally:
        print(message_extraction_successful)
        return messages,message_extraction_successful

def deleteSQSMessage(receipthandle):

    response = ''
    sqsurl =  os.environ['SQSURL']
    rgionname = os.environ['SQSRegionName']
    message_deletion_successful = False
    session = boto3.session.Session()
    sqs_client = session.client(
                service_name='sqs',
                region_name=rgionname
            )
    try:
        response = sqs_client.delete_message(
            QueueUrl=sqsurl,
            ReceiptHandle=receipthandle,
        )
        print(response)
        message_deletion_successful = True
    except Exception as e:
        print("Error setting default ebs encryption. Error : {}".format(e))
        raise
    finally:
        print(message_deletion_successful)
        return response,message_deletion_successful

def send_delete_request_alert(messagedata,account_name,environment):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        #environment = messagedata['ResourceProperties']['environment_type'].lower()
        #account_name = messagedata['ResourceProperties']['account_name'].lower()
        account_id = messagedata['ResourceProperties']['account_id']
        kms_resource = messagedata['ResourceProperties']['kms_resource']
        kms_region = messagedata['ResourceProperties']['kms_region']

        message = '\n' + \
        'AWS account id: ' + account_id + '\n' + \
        'AWS account name: ' + account_name + '\n' + \
        'KMS resource to be deleted: ' + kms_resource + '\n' + \
        'Region where it should be deleted: ' + kms_region

        subject = "KMS product KMS key(s) delete request, please check with customer"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))
        raise

def send_create_failure_alert(messagedata,account_name,environment):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        #environment = messagedata['ResourceProperties']['environment_type'].lower()
        #account_name = messagedata['ResourceProperties']['account_name'].lower()
        account_id = messagedata['ResourceProperties']['account_id']
        kms_resource = messagedata['ResourceProperties']['kms_resource']
        kms_region = messagedata['ResourceProperties']['kms_region']

        message = '\n' + \
        'AWS account id: ' + account_id + '\n' + \
        'AWS account name: ' + account_name + '\n' + \
        'KMS resource could not be created: ' + kms_resource + '\n' + \
        'Region where it should have been created: ' + kms_region

        subject = "KMS product KMS key(s) create failure, please check logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))
        raise

def get_account_name(account_id):

    is_account_name_retrieved = False
    get_describe_account_response = ''
    session = boto3.session.Session()
    client = session.client(
        service_name='organizations',
        region_name='us-east-1'
    )

    try:
        get_describe_account_response = client.describe_account(
            AccountId=account_id
        )
        is_account_name_retrieved = True
    except botocore.exceptions.ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return get_describe_account_response,is_account_name_retrieved

def get_account_envtype(account_id): 
    envtype_tag = "env-type"
    qadatatype_tag = "sensitive-nonprod"
    is_envtype_available = False
    environment = ""
    qadatatype = ""
    session = boto3.session.Session()
    client = session.client(
        service_name='organizations',
        region_name='us-east-1'
    )
    try:
        tagdict = client.list_tags_for_resource(
            ResourceId=account_id,
        )
        for tag in tagdict['Tags']:
            if tag['Key'] == envtype_tag:
                environment = tag['Value']
            elif tag['Key'] == qadatatype_tag:
                qadatatype = tag['Value']            

        if environment:
            print(environment)
            environment= environment.lower()
            is_envtype_available = True
    except Exception as e:
        print(e)
        raise
    finally:
        return environment,qadatatype,is_envtype_available

def checkInputParameters(messagedata):

    all_parameters_available = True
    try:
        account_id = messagedata['ResourceProperties']['account_id']
        kms_resource = messagedata['ResourceProperties']['kms_resource']
        kms_region = messagedata['ResourceProperties']['kms_region']
    except Exception as e:
        print("one or more parameters missing:", e)
        all_parameters_available = False
        raise
    finally:
        return all_parameters_available

def extractKeyID(credentials,deployregion,newkeyalias):

    kmskeyids = {}
    kmskeyarns = {}
    kmskeyid = ''
    kmskeyarn = ''
    is_kmskeyid_available = False
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
        response = kms_client.list_keys(
        )
        print(response)
        keys = response['Keys']
        length = len(keys)
        try:
            for i in range(length):
                print(i)
                keyid = keys[i]['KeyId']
                keyalias = kms_client.list_aliases(
                   KeyId=keyid,
                   Limit=1 
                )
                print(keyalias)
                if len(keyalias['Aliases']) > 0:
                    aliasname = keyalias['Aliases'][0]['AliasName']
                    aliasarn = keyalias['Aliases'][0]['AliasArn']
                    if newkeyalias in aliasname:
                        print(aliasname)
                        aliasnumeric = aliasname[-5::-1][0]
                        #print(aliasnumeric)
                        kmskeyids[keyid] = int(aliasnumeric)
                        kmskeyarns[aliasarn] = int(aliasnumeric)
        except Exception as e:
            print("Error extracting key id. Error : {}".format(e))  
        finally:
            print(kmskeyids)
            print(kmskeyarns)
            if kmskeyids:
                print(max((value, key) for key, value in kmskeyids.items())[1])
                kmskeyid = max((value, key) for key, value in kmskeyids.items())[1]
                print(kmskeyid)
                kmskeyarn = max((value, key) for key, value in kmskeyarns.items())[1]
                print(kmskeyarn)
                is_kmskeyid_available = True
    except Exception as e:
        print("Error extracting key id. Error : {}".format(e))
    finally:
        return is_kmskeyid_available

def lambda_handler(event,context):
    
    responseStatus = 'FAILED'
    responseData = {}
    messagedata = ''
    is_kms_key_created = False
    #shared_key_for_prd_requested = False
    print(event)
    (messages,message_extraction_successful) = getSQSMessage()
    

    if message_extraction_successful:
        receipthandle = messages[0]['ReceiptHandle']
        body = messages[0]['Body']
        print(body)
        bodydata = json.loads(body)
        print(bodydata)
        message = bodydata["Message"]
        print(message)
        messagedata = json.loads(message)
        print(messagedata)

        all_parameters_available = checkInputParameters(messagedata)
        if all_parameters_available:
            account_id = messagedata['ResourceProperties']['account_id']
            kms_resource = messagedata['ResourceProperties']['kms_resource']
            kms_region = messagedata['ResourceProperties']['kms_region']
            wait_url=messagedata['ResourceProperties']['WaitUrl']
            print(account_id)
            print(kms_resource)
            print(kms_region)
            account_name = "NA"
            environment = "NA"
            
            try:
                #Delete the message from the queue
                (response,message_deletion_successful) = deleteSQSMessage(receipthandle)
                print(message_deletion_successful)
                
                #Retrieve account name from account id
                (response,is_account_name_retrieved) = get_account_name(account_id)
        
                #Retrieve account environment type
                (environment,qadatatype,is_envtype_available) = get_account_envtype(account_id)
        
                if is_account_name_retrieved and is_envtype_available:
                    account_name = response['Account']['Name'].lower()
                    print("account name is:" + account_name)
        
                    #Check if the QA enviornment has sensitive vs non-sensitive data and map it appropriately
                    qa_environment_default = "snp-atn"
                    if environment == "qa":
                        if qadatatype == "sensitive":
                            qa_environment_default = "snp-ats"
        
        
                    environment_mapping = {'ftdev':'oz-inf', 'na':'oz-dev', 'foundation':'cpz-inf', 'sbx':'oz-inf', 'dev':'oz-dev', 'qa':qa_environment_default, 'prd':'cpz-prd'}
        
                    if messagedata['RequestType'] == "Create":
                        print("inside create")
                        #Check if KMS key is already provisioned within that region
                        regiondict = {'us-east-1':'useast1', 'us-east-2':'useast2', 'us-west-1':'uswest1', 'us-west-2':'uswest2'}
                        keyalias = ''
                        if "common" in kms_resource:
                            keyalias = regiondict[kms_region] + "/common"
                        else:
                            keyalias = regiondict[kms_region] + "/secretsmanager"

                        #Assume role of member account before creating Qualys IAM role within member account
                        account_role = 'OrganizationAccountAccessRole'    
                        credentials = assume_role(account_id, account_role)

                        is_kmskeyid_available = extractKeyID(credentials,kms_region,keyalias)

                        #Create new key if KMS key id doesn't exist already        
                        if not is_kmskeyid_available:
                            print("inside key creation")
                            #kmsresources = kms_resource.split(",")
                            #kmsregions = kms_region.split(",")
                        
                            #environment_mapping = {'ftdev':'oz-inf', 'sbx':'oz-inf', 'dev':'oz-dev', 'qa':'snp-atn', 'prd':'cpz-prd'}
                        
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
                            #length = len(kmsresources)
                            #for i in range(length):
                            # resource = kmsresources[i]
                            # print(resource)
                            # if environment == "prd" and resource == "common":
                            #     shared_key_for_prd_requested = True
                            #     break
                            #iterate through all defined kmsregions to deploy the keys
                            #for deployregion in kmsregions:
                            #Create key policy for the specific resource
                            keypolicy = ''
                            if "common" in kms_resource:
                                keydescription = "default KMS for all resources outside of s3,ebs,efs,rds,secretsmanager" 
                                keypolicy = createPolicyForShared(account_id,kms_region)
                            else:
                                keydescription = "default KMS for secretsmanager"
                                keypolicy = createPolicyForSM(account_id,kms_region)

                            print(keypolicy)
                            key_alias_region = kms_region.replace('-', '')
                            keyalias = "alias/{0}/{1}/{2}/0/kek".format(account_name,key_alias_region,kms_resource)

                            #Create CMK
                            (keyid,keyarn,is_cmk_created) = create_cmk(credentials,keydescription,keypolicy,environment,kms_region)
                            print("Key id:"+ str(keyid))
                            print("Key arn:"+ str(keyarn))
                            keyalias = "alias/{0}/{1}/{2}/0/kek".format(account_name,key_alias_region,kms_resource)
                            time.sleep(5)
                            if is_cmk_created:
                                #Obtain import token and wrapping key
                                (importtoken,wrapping_key,extract_token_and_key_successful) = get_importtoken_and_wrappingkey(credentials,keyid,kms_region)
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
                                        import_key_material_successful = import_key_material(credentials,keyid,importtoken,wrappedkey,kms_region)
                                        time.sleep(5)
                                        if import_key_material_successful:
                                            #Create key alias
                                            (response,create_key_alias_successful) = create_key_alias(credentials,keyid,keyalias,kms_region)
                                            time.sleep(5)
                                            if create_key_alias_successful:
                                                is_kms_key_created = True
                            print(is_kms_key_created)
                            #print (shared_key_for_prd_requested)

                            #Check if KMS key was created successfully
                            if not is_kms_key_created:
                                send_create_failure_alert(messagedata,account_name,environment)
                            responseStatus = 'SUCCESS'
                            responseData['is_kms_key_created'] = is_kms_key_created
                            sendWaitHandleResponse(wait_url, context, responseStatus, responseData)
                        else:
                            print("KMS key already available for that region")
                            send_create_failure_alert(messagedata,account_name,environment)
                    else:
                        #Delete the KMS keys
                        print("KMS keys to be deleted")
                        responseData['kms_delete_request'] = True
                        send_delete_request_alert(messagedata,account_name,environment)
                        responseStatus = 'SUCCESS'
                        sendWaitHandleResponse(messagedata, context, responseStatus, responseData)
                else:
                    #Account name could not be retrieved
                    print("Account name could not be retrieved")
                    responseData['account_name_retrieval_failed'] = True
                    send_create_failure_alert(messagedata,"NA",environment)
                    responseStatus = 'SUCCESS'
                    #sendWaitHandleResponse(messagedata, context, responseStatus, responseData)
            except Exception as e:
                print('Signaling failure to CloudFormation:',e)
                send_create_failure_alert(messagedata,account_name,environment)
                responseStatus = 'FAILED'
                #sendWaitHandleResponse(messagedata, context, responseStatus, {})
        else:
            print("not all parameters were passed correctly")
    else:
        print('Message extraction unsuccessful.')