from __future__ import print_function
import boto3
import requests
import json
import logging
import os
import base64

logger = logging.getLogger()
logger.setLevel(logging.INFO)
topic_arn = os.environ['topic_arn']
approval_url= os.environ['approval_url']+'?waitUrl='
sns   = boto3.resource('sns')
topic = sns.Topic(topic_arn)
responseData = {'Staus':'Completed'}

def lambda_handler(event, context):
    #logger.info(json.dumps(event))
    if event['RequestType'] != 'Create':
        sendResponse(event, context,'SUCCESS',responseData)
        return
    wait_url=event['ResourceProperties']['WaitUrl'].encode()
    email_id=event['ResourceProperties']['EmailID']
    organizationUnitName=event['ResourceProperties']['organizationUnitName']
    accountName=event['ResourceProperties']['accountName']
    accountType=event['ResourceProperties']['accountType']
    remediationGroup=event['ResourceProperties']['remediationGroup']
    environmentType=event['ResourceProperties']['environmentType']
    qaDataType=event['ResourceProperties']['qaDataType']
    networkRegions=event['ResourceProperties']['networkRegions']
    costCenter=event['ResourceProperties']['costCenter']
    ppmcID=event['ResourceProperties']['ppmcID']
    usageID=event['ResourceProperties']['usageID']
    toc=event['ResourceProperties']['toc']
    shutDownPeriod=event['ResourceProperties']['shutDownPeriod']
    expiryDate=event['ResourceProperties']['expiryDate']
    poc=event['ResourceProperties']['poc']

    encoded_url=base64.b64encode(wait_url);
    response = topic.publish(
    Subject='Request for approval to launch Stack for Account Vending Product',
    Message='Hello Approver, \n\n' +
        'An user has launched the AWS account vending product through Service Now portal.\n\
        Please find details of the request below and take appropriate action\n\n' +
        'Organization Unit:' +organizationUnitName+
        '\nApplication Name:' +accountName+
        '\nAccount Type:' +accountType+
        '\nEnvironment Type:' +environmentType+
        '\nType of data:' +qaDataType+
        '\nNetwork Regions:' +networkRegions+
        '\nRemediation Group:' +remediationGroup+
        '\nCost Center:' +costCenter+
        '\nPPMC ID:' +ppmcID+
        '\nATM ID:' +usageID+
        '\nTechnology Oversight Committee:' +toc+
        '\nShut Down Period:' +shutDownPeriod+
        '\nExpiry Date for account:' +expiryDate+
        '\nPoint of Contact:' +poc+
        '\n\nEnd-user Email ID : '+email_id+
        '\nKindly approve by clicking the below URL.\n\n'+
            approval_url+encoded_url.decode()+
        '\n\nPlease ignore if you dont want the stack to be launched.\n\
        Thanks,\n\
        Product Approval Team\n')
    sendResponse(event, context,'SUCCESS',responseData)

def sendResponse(event, context, responseStatus, responseData):
    response_body={'Status': responseStatus,
            'Reason': 'See the details in CloudWatch Log Stream ' + context.log_stream_name,
            'PhysicalResourceId': context.log_stream_name ,
            'StackId': event['StackId'],
            'RequestId': event['RequestId'],
            'LogicalResourceId': event['LogicalResourceId'],
            'Data': responseData}
    try:
        response = requests.put(event['ResponseURL'],
                        data=json.dumps(response_body))
        return True
    except Exception as e:
        logger.info("Failed executing HTTP request: {}".format(e.code))
    return False