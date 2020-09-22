import os
import boto3
import logging
import time
import botocore

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
            logger.error(e)
            logger.error("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def getGovernanceLogGroup(credentials,loggroupprefix,deployregion):

    response = ''
    session = boto3.session.Session()
    cwlogs_client = session.client(
                service_name='logs',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
    )
    try:
        response = cwlogs_client.describe_log_groups(
            logGroupNamePrefix=loggroupprefix
        )
        #logger.info(response)
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
    finally:
        return response

def tagLogGroups(credentials,logGroupNames,deployregion):

    are_loggroups_tagged = {}
    session = boto3.session.Session()
    cwlogs_client = session.client(
                service_name='logs',
                region_name=deployregion,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
    )
    try:
        for logGroupName in logGroupNames:
            #logger.info('Tagging resource ' + logGroupName)
            response = cwlogs_client.tag_log_group(logGroupName=logGroupName, tags={'usage-id': os.environ['UsageId'], 'toc': os.environ['TOC'], 'ppmc-id': os.environ['PPMCId'], 'cost-center': os.environ['CostCenter'], 'exp-date': os.environ['ExpDate'], 'env-type': os.environ['EnvType'], 'sd-period': os.environ['SDPeriod']})
            if '200' in str(response['ResponseMetadata']['HTTPStatusCode']):
                are_loggroups_tagged.update({logGroupName:True}) 
            #logger.info(response)
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
    finally:
        logger.info(are_loggroups_tagged)
        return are_loggroups_tagged

def lambda_handler(event, context):

    loggroups_tagged_by_region = {}
    account_id = event['account_id']
    #Assume role of member account before creating Qualys IAM role within member account
    account_role = 'OrganizationAccountAccessRole'
    regions = ["us-east-1","us-west-1","us-east-2","us-west-2"]

    try:    
        credentials = assume_role(account_id, account_role)
        #iterate through all US regions
        for deployregion in regions:
            logger.info(deployregion)
            logGroupPrefixes = {'/aws/lambda/StackSet-CFAutoTagSnapshots','/aws/lambda/StackSet-CFAccountBaseline','/aws/lambda/StackSet-CFTagCompliance','/aws/lambda/TrustedAdvisor*'}
            #logGroupPrefixes = {'/aws/lambda/SC'}
            logGroupNames = []
            for logGroupPrefix in logGroupPrefixes:
                logGroupsDict = getGovernanceLogGroup(credentials,logGroupPrefix,deployregion)
                logGroupsList = logGroupsDict['logGroups']
                length = len(logGroupsList)

                for i in range(length):
                    logGroupName = logGroupsList[i]['logGroupName']
                    logGroupNames.append(logGroupName)
            response = tagLogGroups(credentials,logGroupNames,deployregion)
            loggroups_tagged_by_region.update({deployregion:response})
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        raise
    finally:
        return event