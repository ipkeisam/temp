from __future__ import print_function
import boto3
import botocore
import time
import os

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
    is_okta_stack_created = False
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
                is_okta_stack_created = True
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_okta_stack_created

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

    print(event)
    account_id = event['account_id']
    print("Account Id:" + account_id)

    account_role = 'OrganizationAccountAccessRole'
    sourcebucket = os.environ['SourceBucket']
    baselineiamstack = os.environ['BaselineIAMStack']
    baselineiamtemplate = os.environ['BaselineIAMTemplate']

    credentials = assume_role(account_id, account_role)

    # provision IAM resources within new account
    template = get_template(sourcebucket,baselineiamtemplate)
    print(template)
    is_okta_stack_created = deploy_iam(credentials, template, baselineiamstack, "us-west-1")
    print("IAM roles created successfully:"+ str(is_okta_stack_created))
    event['is_okta_stack_created'] = is_okta_stack_created

    return event