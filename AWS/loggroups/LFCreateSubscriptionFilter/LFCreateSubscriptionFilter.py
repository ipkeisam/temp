import boto3
import botocore
import time
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def create_subscription_filters(credentials,filtername,destinationArn,logGroupName,deployregion):
    subscription_filter_created = False
    session = boto3.session.Session()
    # Create CloudWatchLogs client
    cloudwatch_logs = session.client(
        service_name='logs',
        region_name=deployregion,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        # Create a subscription filter
        response = cloudwatch_logs.put_subscription_filter(
            destinationArn=destinationArn,
            filterName=filtername,
            filterPattern='',
            logGroupName=logGroupName,
        )
        logger.info(response)
        subscription_filter_created = True
    except botocore.exceptions.ClientError as e:
        logger.info("The request could not be completed:", e)
    finally:
        return response

def get_account_filters(accountid):

    sourcebucket = os.environ['SOURCE_BUCKET']
    filename = os.environ['LOGGROUP_MAPPING_FILE']
    s3 = boto3.resource('s3','us-east-1')
    account_loggroups = []
    #standard_loggroups = []
    try:
        obj = s3.Object(sourcebucket,filename)
        all_filters = json.loads(obj.get()['Body'].read().decode('utf-8'))
        #standard_loggroups = all_filters["standard_loggroups"]
        account_specific_loggroups = all_filters["account_specific"]
        if accountid in str(account_specific_loggroups):
            account_loggroups = account_specific_loggroups[accountid]['loggroups']
            logger.info(account_loggroups)
    except Exception as e:
        print("Error accessing the source bucket. Error : {}".format(e))
    finally:
        return account_loggroups

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

def lambda_handler(event,context):

    is_subscription_filter_created = False
    KinesisAccount = os.environ['KINESIS_ACCOUNT']
    regiondict = {'us-east-1':'east1', 'us-east-2':'east2', 'us-west-1':'west1', 'us-west-2':'west2'}
    
    try:
        region = event['region']
        detail = event['detail']
        eventname = detail['eventName']
        account_id = detail['userIdentity']['accountId']

        logger.info('region: ' + str(region))
        logger.info('eventName: ' + str(eventname))
        logger.info('detail: ' + str(detail))

        if not detail['requestParameters']:
            logger.warning('No responseElements found')
            if detail['errorCode']:
                logger.error('errorCode: ' + detail['errorCode'])
            if detail['errorMessage']:
                logger.error('errorMessage: ' + detail['errorMessage'])
            return False

        logGroupName = detail['requestParameters']['logGroupName']
        logger.info(logGroupName)
        loggrouplist = get_account_filters(account_id)

        if loggrouplist:
            loggrouparray = []
            filternamearray = []
            subscriptionfilterarray = []
            length = len(loggrouplist)
            for i in range(length):
                loggrouparray.append(loggrouplist[i]['loggroup'])
                filternamearray.append(loggrouplist[i]['filtername'])
                subscriptionfilterarray.append(loggrouplist[i]['subscriptionfilter'])
                logger.info(loggrouparray)
                logger.info(filternamearray)
                logger.info(subscriptionfilterarray)
            filterresponseData = {}
            for loggroup in loggrouparray:
                if loggroup in logGroupName:
                    logger.info("log group present")
                    #Assume role of member account before creating Qualys IAM role within member account
                    account_role = 'OrganizationAccountAccessRole'    
                    credentials = assume_role(account_id, account_role)
                    
                    loggroupindex = loggrouparray.index(loggroup)
                    logger.info(loggroupindex)
                    filterName =  '{0}-{1}'.format(filternamearray[loggroupindex], regiondict[region])
                    logger.info(filterName)
                    destinationARN = 'arn:aws:logs:{0}:{1}:destination:{2}-{3}'.format(region, KinesisAccount, subscriptionfilterarray[loggroupindex], regiondict[region])
                    logger.info(destinationARN)
                    create_filter_response = create_subscription_filters(credentials,filterName,destinationARN,logGroupName,region)
                    logger.info("Create filter response "+str(create_filter_response))
                    logger.info(create_filter_response['ResponseMetadata']['HTTPStatusCode'])
                    if '200' in str(create_filter_response['ResponseMetadata']['HTTPStatusCode']):
                        is_subscription_filter_created = True
                    break 
        logger.info(is_subscription_filter_created)
        event['is_subscription_filter_created'] = is_subscription_filter_created
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        return False