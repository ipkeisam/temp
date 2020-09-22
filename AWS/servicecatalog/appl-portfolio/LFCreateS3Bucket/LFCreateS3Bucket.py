from __future__ import print_function
import boto3
import botocore
import json
import requests
import os

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

def extractKeyID(region,s3alias):

    kmskeyids = {}
    kmskeyarns = {}
    kmskeyid = ''
    kmskeyarn = ''
    is_kmskeyid_available = False
    session = boto3.session.Session()
    kms_client = session.client(
                service_name='kms',
                region_name=region
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

def createBucket(bucketname,region):

    is_bucket_created = False
    response = ''
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
            )
    try:
        if region == 'us-east-1':
            response = s3_client.create_bucket(
                Bucket=bucketname
            )
        else:
            response = s3_client.create_bucket(
                Bucket=bucketname,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                }
            )
        is_bucket_created = True
        print(is_bucket_created)
    except botocore.exceptions.ClientError as e:
        print("Error creating bucket. Error : {}".format(e))
    finally:
        print(is_bucket_created)
        return is_bucket_created

def putPublicAccessBlock(bucketname,region):

    is_public_access_blocked = False
    response = ''
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
            )
    try:
        response = s3_client.put_public_access_block(
            Bucket=bucketname,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(response.text)
        is_public_access_blocked = True
    except botocore.exceptions.ClientError as e:
        print("Error creating bucket. Error : {}".format(e))
    finally:
        return is_public_access_blocked

def encryptBucket(bucketname,region,kmskeyid):

    is_bucket_encrypted = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
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

def putBucketLogging(bucketname,targetbucket,region):

    is_bucket_logging_enabled = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
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

def setBucketTags(bucketname,tagdict,region): 

    is_bucket_tagging_enabled = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
            )
    mandatory_tags = {
                    "usage-id":tagdict['usageid'],
                    "toc":tagdict['toc'],
                    "ppmc-id":tagdict['ppmcid'],
                    "cost-center":tagdict['costcenter'],
                    "exp-date":tagdict['expdate'],
                    "env-type":tagdict['envtype'],
                    "sd-period":tagdict['sdperiod']
    }
    print(mandatory_tags)
    print('Tagging resource ' + bucketname)
    try:
        response = s3_client.put_bucket_tagging(
            Bucket=bucketname,
            Tagging={
                'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in mandatory_tags.items()]
            }
        )
        print(response)
        is_bucket_tagging_enabled = True
    except Exception as e:
        print(e)
    finally:
        return is_bucket_tagging_enabled

def putBucketVersioning(bucketname,region):

    is_bucket_versioning_enabled = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
            )
    try:
        response = s3_client.put_bucket_versioning(
            Bucket=bucketname,
            VersioningConfiguration={
                'Status': 'Enabled'
            }
        )
        print(response)
        is_bucket_versioning_enabled = True
    except Exception as e:
        print("Error extracting key id. Error : {}".format(e))
    finally:
        return is_bucket_versioning_enabled

def putBucketReplication(accountid,sourcebucketname,destinationbucketname,sourceregion,destinationregion,destinationkmskeyarn):

    is_bucket_replication_enabled = False
    destinationbucketarn = "arn:aws:s3:::" + destinationbucketname
    rolename = "arn:aws:iam::" + accountid + ":role/ReplicateS3BucketsAllDay"
    print(rolename)
    print(destinationbucketarn)
    print(destinationkmskeyarn)
    print(sourcebucketname)
    s3regiondict = {'us-east-1':'useast1', 'us-east-2':'useast2', 'us-west-1':'uswest1', 'us-west-2':'uswest2'}
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                #region_name=sourceregion,
            )
    try:
        id = "Enable_replication_from_" + s3regiondict[sourceregion] + "_to_" + s3regiondict[destinationregion]
        response = s3_client.put_bucket_replication(Bucket=sourcebucketname, ReplicationConfiguration={
                "Role": rolename,
                "Rules": [
                    {
                        "ID": id,
                        "Status": "Enabled",
                        "SourceSelectionCriteria": {
                            "SseKmsEncryptedObjects": {
                                "Status": "Enabled"
                            }
                        },
                        "Destination": {
                            "Bucket": destinationbucketarn,
                            "EncryptionConfiguration": {
                                "ReplicaKmsKeyID": destinationkmskeyarn
                            }
                        },
                        "Prefix": ''
                    },
                ]
            }
        )
        print(response)
        is_bucket_replication_enabled = True
    except Exception as e:
        print("Error setting up replication. Error : {}".format(e))
    finally:
        return is_bucket_replication_enabled

def deleteBucket(bucketname,region):

    is_bucket_deleted = False
    is_bucket_objects_deleted = False
    session = boto3.session.Session()
    s3_client = session.client(
                service_name='s3',
                region_name=region
            )
    try:
        #First check if the bucket has any objects in it and delete the objects first
        response = s3_client.list_objects_v2(
            Bucket=bucketname
        )
        if response['KeyCount'] > 0:
            objectlist = response['Contents']
            length = len(objectlist)
            newobjectlist = []
            for i in range(length):
                objectkey = objectlist[i]['Key']
                objectdict = {'Key':objectkey}
                newobjectlist.append(objectdict)
            print(newobjectlist)

            response = s3_client.delete_objects(
                Bucket=bucketname,
                Delete={
                    'Objects': newobjectlist,
                    'Quiet': True
                }
            )
        is_bucket_objects_deleted = True
    except Exception as e:
        print("Error deleting bucket objects. Error : {}".format(e))
    finally:
        print(is_bucket_objects_deleted)
    
    try:
        if is_bucket_objects_deleted:
            #Then delete the empty bucket
            response = s3_client.delete_bucket(
                Bucket=bucketname
            )
            is_bucket_deleted = True
            print(is_bucket_deleted)
    except Exception as e:
        print("Error deleting bucket. Error : {}".format(e))
    finally:
        print(is_bucket_deleted)
        return is_bucket_deleted

def send_delete_request_alert(account_id,bucketname,enable_replication):
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
        'S3 bucket replicated: ' + enable_replication

        subject = "S3 product Prod Bucket delete request, please check with client"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def send_delete_failure_alert(account_id,bucketname):
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
        'S3 bucket name: ' + bucketname

        subject = "S3 product Bucket deletion failed, please check the logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def send_create_failure_alert(account_id,bucketname):
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
        'S3 bucket name: ' + bucketname

        subject = "S3 product Bucket creation failed, please check the logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

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

def lambda_handler(event,context):

    responseStatus = 'SUCCESS'
    responseData = {}
    account_id = event['ResourceProperties']['accountid']
    sourceregion = event['ResourceProperties']['region']
    bucketname = event['ResourceProperties']['bucketname'].lower()

    costcenter = event['ResourceProperties']['costcenter']
    envtype = event['ResourceProperties']['envtype']
    expdate = event['ResourceProperties']['expdate']
    ppmcid = event['ResourceProperties']['ppmcid']
    toc = event['ResourceProperties']['toc']
    sdperiod = event['ResourceProperties']['sdperiod']
    usageid = event['ResourceProperties']['usageid']
    
    enable_replication = event['ResourceProperties']['enable_replication']
    destinationregion = event['ResourceProperties']['replication_region']
    
    s3regiondict = {'us-east-1':'useast1', 'us-east-2':'useast2', 'us-west-1':'uswest1', 'us-west-2':'uswest2'}
    #Check if the product is getting created or deleted and take appropriapte action

    if event['RequestType'] == "Create":
        #Create Bucket
        is_bucket_created = createBucket(bucketname,sourceregion)
        if is_bucket_created:

            #Tag the bucket with the mandatory values
            tagdict = {'costcenter':costcenter, 'envtype':envtype, 'expdate': expdate, 'ppmcid':ppmcid, 'toc':toc, 'sdperiod':sdperiod, 'usageid':usageid}
            is_bucket_tagging_enabled = setBucketTags(bucketname,tagdict,sourceregion)
            if not is_bucket_tagging_enabled:
                send_compliance_application_failure_alert(account_id,bucketname,"Applying Tags failed")
            #Enable encryptin for the bucket with correct S3 encryption key
            s3alias = s3regiondict[sourceregion] + "/s3"
            (kmskeyid,kmskeyarn,is_kmskeyid_available) = extractKeyID(sourceregion,s3alias)
            print(is_kmskeyid_available)
            if is_kmskeyid_available:
                is_bucket_encrypted = encryptBucket(bucketname,sourceregion,kmskeyid)
                if not is_bucket_encrypted:
                    send_compliance_application_failure_alert(account_id,bucketname,"KMS encryption failed")
            else:
                send_compliance_application_failure_alert(account_id,bucketname,"KMS encryption, no S3 alias found")

            # #Apply public access block on the bucket
            # is_public_access_blocked = putPublicAccessBlock(bucketname,sourceregion)
            # if not is_public_access_blocked:
            #     send_compliance_application_failure_alert(account_id,bucketname,"Public Access Block failed")

            #Enable access logging for the bucket
            regiondict = {'us-east-1':'e1', 'us-east-2':'e2', 'us-west-1':'w1', 'us-west-2':'w2'} 
            targetbucket = "{0}-s3-access-logs-{1}".format(account_id,regiondict[sourceregion])
            is_bucket_logging_enabled = putBucketLogging(bucketname,targetbucket,sourceregion)
            if not is_bucket_logging_enabled:
                send_compliance_application_failure_alert(account_id,bucketname,"Enable Bucket Access Logging failed")

            if envtype == "prd" and enable_replication == "true":

                #Enable bucket versioning in source bucket
                is_bucket_versioning_enabled = putBucketVersioning(bucketname,sourceregion)
                if not is_bucket_versioning_enabled:
                    send_compliance_application_failure_alert(account_id,bucketname,"Enable Bucket Versioning failed")

                regiondict = {'us-east-1':'e1', 'us-east-2':'e2', 'us-west-1':'w1', 'us-west-2':'w2'}
                destinationbucketname = bucketname + "-" + regiondict[destinationregion]
                
                #Create bucket in replication region with the same steps as the original bucket
                is_destination_bucket_created = createBucket(destinationbucketname,destinationregion)         
                
                if is_destination_bucket_created:
                    #Tag the bucket with the mandatory values
                    tagdict = {'costcenter':costcenter, 'envtype':envtype, 'expdate': expdate, 'ppmcid':ppmcid, 'toc':toc, 'sdperiod':sdperiod, 'usageid':usageid}
                    is_bucket_tagging_enabled = setBucketTags(destinationbucketname,tagdict,destinationregion)
                    if not is_bucket_tagging_enabled:
                        send_compliance_application_failure_alert(account_id,destinationbucketname,"Applying Tags failed")

                    #Enable encryptin for the bucket with correct S3 encryption key
                    s3alias = s3regiondict[destinationregion] + "/s3"
                    (destinationkmskeyid,destinationkmskeyarn,is_kmskeyid_available) = extractKeyID(destinationregion,s3alias)
                    print(is_kmskeyid_available)
                    if is_kmskeyid_available:
                        is_bucket_encrypted = encryptBucket(destinationbucketname,destinationregion,destinationkmskeyarn)
                        if not is_bucket_encrypted:
                            send_compliance_application_failure_alert(account_id,destinationbucketname,"KMS encryption failed")
                    else:
                        send_compliance_application_failure_alert(account_id,destinationbucketname,"KMS encryption, no S3 alias found")

                    # #Apply public access block on the bucket
                    # is_public_access_blocked = putPublicAccessBlock(destinationbucketname,destinationregion)
                    # if not is_public_access_blocked:
                    #     send_compliance_application_failure_alert(account_id,destinationbucketname,"Public Access Block failed")

                    #Enable access logging for the bucket
                    targetbucket = "{0}-s3-access-logs-{1}".format(account_id,regiondict[destinationregion])
                    is_bucket_logging_enabled = putBucketLogging(destinationbucketname,targetbucket,destinationregion)
                    if not is_bucket_logging_enabled:
                        send_compliance_application_failure_alert(account_id,destinationbucketname,"Enable Bucket Access Logging failed")

                    #Enable bucket versioning
                    is_bucket_versioning_enabled = putBucketVersioning(destinationbucketname,destinationregion)
                    if not is_bucket_versioning_enabled:
                        send_compliance_application_failure_alert(account_id,destinationbucketname,"Enable Bucket Versioning failed")
                    
                    #Enable replication:
                    is_bucket_replication_enabled = putBucketReplication(account_id,bucketname,destinationbucketname,sourceregion,destinationregion,destinationkmskeyarn)
                    if not is_bucket_replication_enabled:
                        send_compliance_application_failure_alert(account_id,bucketname,"Enable Bucket replication failed")
                else:
                    send_create_failure_alert(account_id,destinationbucketname)
        else:
            send_create_failure_alert(account_id,bucketname)
                    
        responseData['bucket_created'] = is_bucket_created
    else:
        #The bucket is being deleted, take appropriate action
        if envtype == "prd":
            #As a precauitonary measure do not delete the bucket but send notification to PDS team there is request to delete
            print("prod bucket , send notification for deletion")
            responseData['prod_bucket_deleted'] = False
            send_delete_request_alert(account_id,bucketname,enable_replication)
        else:
            #Delete bucket
            is_bucket_deleted = deleteBucket(bucketname,sourceregion)
            if not is_bucket_deleted:
                send_delete_failure_alert(account_id,bucketname)
            responseData['bucket_deleted'] = is_bucket_deleted
    sendTriggerLambdaResponse(event, context, responseStatus, responseData)