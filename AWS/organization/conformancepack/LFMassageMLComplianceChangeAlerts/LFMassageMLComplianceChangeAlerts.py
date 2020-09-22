from __future__ import print_function
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

def lambda_handler(event, context):

    try:

        detail = event['detail']

        if detail['newEvaluationResult']:
            complianceType = detail['newEvaluationResult']['complianceType']
            if complianceType == "NON_COMPLIANT":
                configRuleName = detail['configRuleName']
                resourceId = detail['resourceId']
                region = detail['awsRegion']
                accountid = detail['awsAccountId']
                resourceType = detail['resourceType']
                subject = "Non compliant resource: " + resourceId + ". Please take remedial action."
                message = '\n' + \
                'AWS config rule: ' + configRuleName.split(':')[0] + '\n' + \
                'AWS config type: ' + complianceType + '\n' + \
                'AWS account id: ' + accountid + '\n' + \
                'AWS region: ' + region + '\n' + \
                'AWS resource type: ' + resourceType + '\n' + \
                'AWS resource: ' + resourceId
                response = send_compliance_alert(message,subject)
            else:
                return False
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        return False