from __future__ import print_function
import boto3
import botocore
import sys
import argparse
import os
import time
import urllib
import json
from botocore.vendored import requests

def deploy_autotagging(stacksetname, accountid, set_region):
    is_autotag_stack_created = False
    client = boto3.client('cloudformation', region_name=set_region)
    print("Updating stackset " + stacksetname + " in " + accountid)
    try:
        create_stack_response = client.create_stack_instances(
            StackSetName=stacksetname,
            Accounts=[
                accountid,
            ],
            Regions=[
                'us-west-1',
                'us-west-2',
                'us-east-1',
                'us-east-2',
            ]
        )
        is_autotag_stack_created = True
        return is_autotag_stack_created

    except botocore.exceptions.ClientError as e:
        print("Error deploying stack: {}".format(e))
        return is_autotag_stack_created

def create_template(costcenter,ppmcid,toc,usageid,expdate,envtype,sdperiod):
    template =   "AWSTemplateFormatVersion: 2010-09-09\n" + \
    "Description: Wrapper Template for Auto Tag OCP Account\n" + \
    "Parameters:\n" + \
    "   AccountCostCenter:\n" + \
    "       Default: " + costcenter +  "\n" + \
    "       Type: String\n" + \
    "   AccountPPMCId:\n" + \
    "       Default: " + ppmcid +  "\n" + \
    "       Type: String\n" + \
    "   AccountTOC:\n" + \
    "       Default: " + toc + "\n" + \
    "       Type: String\n" + \
    "   AccountUsageId:\n" + \
    "       Default: " + usageid + "\n" + \
    "       Type: String\n" + \
    "   AccountExpDate:\n" + \
    "       Default: " + expdate + "\n" + \
    "       Type: String\n" + \
    "   AccountEnvType:\n" + \
    "       Default: " + envtype + "\n" + \
    "       Type: String\n" + \
    "   AccountSDPeriod:\n" + \
    "       Default: " + sdperiod + "\n" + \
    "       Type: String\n" + \
    "Resources:\n" + \
    "   AutoTagResources:\n" + \
    "      Type: 'AWS::CloudFormation::Stack'\n" + \
    "      Properties:\n" + \
    "          Parameters:\n" + \
    "              AccountCostCenter: !Ref AccountCostCenter\n" + \
    "              AccountPPMCId: !Ref AccountPPMCId\n" + \
    "              AccountTOC: !Ref AccountTOC\n" + \
    "              AccountUsageId: !Ref AccountUsageId\n" + \
    "              AccountExpDate: !Ref AccountExpDate\n" + \
    "              AccountEnvType: !Ref AccountEnvType\n" + \
    "              AccountSDPeriod: !Ref AccountSDPeriod\n" + \
    "          Tags:\n" + \
    "            - Key: cost-center\n" + \
    "              Value: 524154\n" + \
    "            - Key: ppmc-id\n" + \
    "              Value: 69058\n" + \
    "            - Key: usage-id\n" + \
    "              Value: BB00000008\n" + \
    "            - Key: toc\n" + \
    "              Value: ETOC\n" + \
    "            - Key: exp-date\n" + \
    "              Value: 99-00-9999\n" + \
    "            - Key: env-type\n" + \
    "              Value: prod\n" + \
    "            - Key: sd-period\n" + \
    "              Value: na\n" + \
    "            - Key: category\n" + \
    "              Value: governance\n" + \
    "          TemplateURL: https://organization-cftemplates.s3-us-west-1.amazonaws.com/CFAutoTagAccount.yml"

    return template

def create_stack_set(stacksetname,accountid,template,set_region):
    is_stackset_created = False
    client = boto3.client('cloudformation', region_name=set_region)
    print("Updating stackset " + stacksetname)
    creating_stackset = True
    try:
        while creating_stackset is True:
            try:
                creating_stackset = False

                response = client.create_stack_set(
                    StackSetName=stacksetname,
                    Description='Stackset to deploy auto tagging to ' + accountid,
                    TemplateBody=template,
                    Capabilities=[
                        'CAPABILITY_IAM',
                        'CAPABILITY_AUTO_EXPAND'
                    ],
                    ExecutionRoleName='AWSCloudFormationStackSetExecutionRole',
                )
                is_stackset_created = True
                time.sleep(30)
            except botocore.exceptions.ClientError as e:
                creating_stackset = True
                print(e)
                print("Retrying...")
                time.sleep(10)

    except botocore.exceptions.ClientError as e:
        print("Error creating stackset: {}".format(e))
        return is_stackset_created

def sendResponse(event, context, responseStatus, responseData):
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

def lambda_handler(event,context):
    responseStatus = 'SUCCESS'
    responseData = {}
    print(event)
    accountid = event['ResourceProperties']['accountid']
    autotagregion = event['ResourceProperties']['autotagregion']
    costcenter = event['ResourceProperties']['costcenter']
    envtype = event['ResourceProperties']['envtype']
    expdate = event['ResourceProperties']['expdate']
    ppmcid = event['ResourceProperties']['ppmcid']
    toc = event['ResourceProperties']['toc']
    usageid = event['ResourceProperties']['usageid']
    sdperiod = event['ResourceProperties']['sdperiod']

    #Create template to be used to create the stack set
    template = create_template(costcenter,ppmcid,toc,usageid,expdate,envtype,sdperiod)
    stacksetname = "CFAutoTag" + accountid + "Wrapper"

    #Create stackset for auto tagging the account
    stacksetresponse = create_stack_set(stacksetname,accountid,template,autotagregion)

    #Deploy auto tagging in all 4 US regions 
    is_autotag_stack_created = deploy_autotagging(stacksetname, accountid, autotagregion)
    print("Tag Compliance alerts deployed successfully:"+ str(is_autotag_stack_created))

    event['is_autotag_stack_created'] = is_autotag_stack_created
    print("Auto Tagging for account " + accountid +  " complete !!")

    responseData = {'Success': 'Auto Tagging setup for account completed.'}
    sendResponse(event, context, responseStatus, responseData)