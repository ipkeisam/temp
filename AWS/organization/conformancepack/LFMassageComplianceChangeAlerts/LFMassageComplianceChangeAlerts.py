from __future__ import print_function
import os
import boto3
import botocore
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

def send_compliance_alert(message,subject):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def putBucketLogging(credentials,bucketname,targetbucket,region):
    is_bucket_logging_enabled = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
    try:
        response = s3_client.put_bucket_logging(
            Bucket=bucketname,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': targetbucket,
                    'TargetPrefix': bucketname
                }
            }
        )
        print(response)
        is_bucket_logging_enabled = True
    except botocore.exceptions.ClientError as e:
        print("Error enabling bucket logging. Error : {}".format(e))
    finally:
        return is_bucket_logging_enabled

def send_compliance_application_failure_alert(account_id,bucketname,compliance_failure):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        message = '\n' + \
        'AWS account id: ' + account_id + '\n' + \
        'S3 bucket name: ' + bucketname + '\n' + \
        'Failed to apply:' + compliance_failure

        subject = "S3 product Failed to apply compliance entity, please check the logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def extractKeyID(credentials,region,s3alias):

    kmskeyids = {}
    kmskeyarns = {}
    kmskeyid = ''
    kmskeyarn = ''
    is_kmskeyid_available = False
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
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
                    if s3alias in aliasname:
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
        return kmskeyid,kmskeyarn,is_kmskeyid_available

def encryptBucket(credentials,bucketname,region,kmskeyid):

    is_bucket_encrypted = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
    try:
        response = s3_client.put_bucket_encryption(
            Bucket=bucketname,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': kmskeyid
                        }
                    }
                ]
            }
        )
        #print(response)
        is_bucket_encrypted = True
    except Exception as e:
        print("Error encrypting bucket. Error : {}".format(e))
    finally:
        print(is_bucket_encrypted)
        return is_bucket_encrypted

def lambda_handler(event, context):
    try:
        detail = event['detail']
        print(detail)
        if detail['newEvaluationResult']:
            complianceType = detail['newEvaluationResult']['complianceType']
            if complianceType == "NON_COMPLIANT":
                configRuleName = detail['configRuleName']
                resourceId = detail['resourceId']
                region = detail['awsRegion']
                accountid = detail['awsAccountId']
                resourceType = detail['resourceType']
                if "OrgConfigRule" in configRuleName:
                    configRuleName = "TagCompliance-OrgConfigRule"
                if "S3BucketSSLRequestsOnly" in configRuleName:
                    return False
                elif "s3-access-logs" in resourceId and "S3BucketLoggingEnabled" in configRuleName:
                    return False
                elif "S3BucketLoggingEnabled" in configRuleName:
                    #Assume role of member account
                    account_role = 'OrganizationAccountAccessRole'
                    credentials = assume_role(accountid, account_role)
                    #Enable access logging for the bucket
                    regiondict = {'us-east-1':'e1', 'us-east-2':'e2', 'us-west-1':'w1', 'us-west-2':'w2'} 
                    targetbucket = "{0}-s3-access-logs-{1}".format(credentials,accountid,regiondict[region])
                    is_bucket_logging_enabled = putBucketLogging(resourceId,targetbucket,region)
                    if not is_bucket_logging_enabled:
                        send_compliance_application_failure_alert(accountid,resourceId,"Enable Bucket Access Logging failed")
                elif "ServerSideEncryptionEnabled" in configRuleName:
                    #Assume role of member account
                    account_role = 'OrganizationAccountAccessRole'
                    credentials = assume_role(accountid, account_role)
                    #Enable encryptin for the bucket with correct S3 encryption key
                    s3regiondict = {'us-east-1':'useast1', 'us-east-2':'useast2', 'us-west-1':'uswest1', 'us-west-2':'uswest2'}
                    s3alias = s3regiondict[region] + "/s3"
                    (kmskeyid,kmskeyarn,is_kmskeyid_available) = extractKeyID(credentials,region,s3alias)
                    print(is_kmskeyid_available)
                    if is_kmskeyid_available:
                        is_bucket_encrypted = encryptBucket(credentials,resourceId,region,kmskeyid)
                        if not is_bucket_encrypted:
                            send_compliance_application_failure_alert(accountid,resourceId,"KMS encryption failed")
                    else:
                        send_compliance_application_failure_alert(accountid,resourceId,"KMS encryption, no S3 alias found")
                else:
                    subject = "Non compliant resource: " + resourceId + ". Please take remedial action."
                    message = '\n' + \
                    'AWS config rule: ' + configRuleName.split('-')[0] + '\n' + \
                    'AWS config type: ' + complianceType + '\n' + \
                    'AWS account id: ' + accountid + '\n' + \
                    'AWS region: ' + region + '\n' + \
                    'AWS resource type: ' + resourceType + '\n' + \
                    'AWS resource: ' + resourceId + '\n\n\n' + \
                    'S3 compliance standards: https://confluence.capgroup.com/display/HCEA/S3' + '\n' + \
                    'S3 product for self provisioning: https://confluence.capgroup.com/display/HCEA/S3+Product' + '\n' + \
                    'Service Catalog HowTo: https://confluence.capgroup.com/display/HCEA/Service+Catalog+Products'
                    if "TagCompliance" in configRuleName:
                        message += '\n' + \
                        'Tagging Standards: https://confluence.capgroup.com/display/HCEA/Resource+Tagging+standards'
                        response = send_compliance_alert(message,subject)
            else:
                return False
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        return False