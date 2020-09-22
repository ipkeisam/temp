from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import os
import urllib
import json
from botocore.vendored import requests

def get_client(service):
    client = boto3.client(service)
    return client

def get_template(sourcebucket,baselinetemplate):

    s3 = boto3.resource('s3','us-east-1')
    try:
        obj = s3.Object(sourcebucket,baselinetemplate)
        print(obj)
        print(obj.get()['Body'].read().decode('utf-8'))
        return obj.get()['Body'].read().decode('utf-8') 
    except botocore.exceptions.ClientError as e:
        print("Error accessing the source bucket. Error : {}".format(e))
        return e

def deploy_iam(credentials, template, stackname, stackregion):
    is_iam_stack_created = False
    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=stackregion)

    creating_stack = True
    try:
        while creating_stack is True:
            try:
                creating_stack = False
                create_stack_response = client.create_stack(
                    StackName=stackname,
                    TemplateBody=template,
                    NotificationARNs=[],
                    Capabilities=[
                        'CAPABILITY_NAMED_IAM',
                    ],
                    OnFailure='ROLLBACK'
                )
            except botocore.exceptions.ClientError as e:
                creating_stack = True
                print(e)
                print("Retrying...")
                time.sleep(10)

        stack_building = True
        print("Stack creation in process...")
        print(create_stack_response)
        while stack_building is True:
            event_list = client.describe_stack_events(StackName=stackname).get("StackEvents")
            stack_event = event_list[0]

            if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
            stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
                stack_building = False
                print("Stack construction complete.")
                is_resource_stack_created = True
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
                #sys.exit(1)
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)
        #stack = client.describe_stacks(StackName=stackname)
        return is_resource_stack_created
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        return is_resource_stack_created

def deploy_resources(credentials, template, stackname, stackregion, account_id):
    is_resource_stack_created = False
    configlogname = "aws-" + account_id + "-config-logs"
    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=stackregion)
    print("Creating stack " + stackname + " in " + account_id)
    creating_stack = True
    try:
        while creating_stack is True:
            try:
                creating_stack = False
                create_stack_response = client.create_stack(
                    StackName=stackname,
                    TemplateBody=template,
                    Parameters=[
                        {
                            'ParameterKey' : 'ConfigLogName',
                            'ParameterValue' : configlogname
                        }
                    ],
                    NotificationARNs=[],
                    Capabilities=[
                        'CAPABILITY_NAMED_IAM',
                    ],
                    OnFailure='ROLLBACK'
                )
            except botocore.exceptions.ClientError as e:
                creating_stack = True
                print(e)
                print("Retrying...")
                time.sleep(10)

        stack_building = True
        print("Stack creation in process...")
        print(create_stack_response)
        while stack_building is True:
            event_list = client.describe_stack_events(StackName=stackname).get("StackEvents")
            stack_event = event_list[0]

            if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
            stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
                stack_building = False
                print("Stack construction complete.")
                is_resource_stack_created = True
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
                #sys.exit(1)
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)
        #stack = client.describe_stacks(StackName=stackname)
        return is_resource_stack_created
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack.There might be an error either accessing the Source bucket or accessing the baseline template from the source bucket.Error : {}".format(e))
        return is_resource_stack_created

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
    event['is_baseline_setup_complete'] = False
    print(event)
    account_id = event['account_id']
    print("Account Id:" + account_id)

    client = get_client('organizations')
    organization_unit_name = os.environ['OrganizationUnitName']
    account_role = 'OrganizationAccountAccessRole'
    sourcebucket = os.environ['SourceBucket']
    baselineiamstack = os.environ['BaselineIAMStack']
    baselineresourcestack = os.environ['BaselineResourceStack']
    scps = os.environ['SCPs']

    baselineiamtemplate = baselineiamstack + ".yml"
    baselineresourcetemplate = baselineresourcestack + ".yml"

    configregions = ["us-west-1","us-east-1","us-east-2","us-west-2"]
    #configregions = ["us-west-1","us-west-2"]

    org_client = get_client('organizations')
    
    try:
        list_roots_response = org_client.list_roots()
        print(list_roots_response)
        root_id = list_roots_response['Roots'][0]['Id']
        print(root_id)
    except:
        root_id = "Error"

    if root_id  is not "Error":

        credentials = assume_role(account_id, account_role)

        # provision IAM resources within new account
        template = get_template(sourcebucket,baselineiamtemplate)
        print(template)
        is_iam_stack_created = deploy_iam(credentials, template, baselineiamstack, "us-west-1")
        print("IAM roles created successfully:"+ str(is_iam_stack_created))
        event['is_iam_stack_created'] = is_iam_stack_created
        #event['is_iam_stack_created'] = True
        
        #provision all other resources within new account
        template = get_template(sourcebucket,baselineresourcetemplate)
        print(template)

        #iterate through all 4 US regions to deploy template
        for deployregion in configregions:
            print(deployregion)
            is_resource_stack_created = deploy_resources(credentials, template, baselineresourcestack, deployregion, account_id)
            print("Resources created successfully:"+ str(is_resource_stack_created))

        event['is_resource_stack_created'] = is_resource_stack_created
        print("Resources deployment for account " + account_id +  " complete !!")

        event['is_baseline_setup_complete'] = True
        root_id = client.list_roots().get('Roots')[0].get('Id')
        #print(root_id)
        #print('Outside try block - {}'.format(organization_unit_name))

        if scps is not None:
            scp_list = scps.split(",")
            for scp in scp_list:
                attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=account_id)
                print("Attach policy response "+str(attach_policy_response))
    else:
        print("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
        #sys.exit(1)
    return event