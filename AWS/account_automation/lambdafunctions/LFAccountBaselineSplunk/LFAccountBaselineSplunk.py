from __future__ import print_function
import boto3
import botocore
import time
import os
import json

def deploy_splunk(stackname, account_id, set_region):
    is_splunk_stack_created = False
    client = boto3.client('cloudformation', region_name=set_region)
    print("Updating stackset " + stackname + " in " + account_id)
    try:
        create_stack_response = client.create_stack_instances(
            StackSetName=stackname,
            Accounts=[
                account_id,
            ],
            Regions=[
                'us-west-1',
                'us-west-2',
                'us-east-1',
                'us-east-2',
            ]
        )
        is_splunk_stack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack: {}".format(e))
        raise
    finally:
        return is_splunk_stack_created

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

def describe_destination_policy(credentials,destinationName,policyregion):
    destinationpolicy = {}
    print(destinationName)
    session = boto3.session.Session()
    # Create CloudWatchLogs client
    cloudwatch_logs = session.client(
        service_name='logs',
        region_name=policyregion,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        # Update destination policy
        describe_destinations_response = cloudwatch_logs.describe_destinations(
            DestinationNamePrefix=destinationName   
        )
        #response = json.loads(describe_destinations_response)
        # length = len(describe_destinations_response['destinations'])
        # for i in range(length):
        print(describe_destinations_response['destinations'][0]['destinationName'])
        data = json.loads(describe_destinations_response['destinations'][0]['accessPolicy'])
        destinationpolicy[destinationName] = json.dumps(data)
        #print(describe_destinations_response)
    except botocore.exceptions.ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return destinationpolicy
        
def create_updated_destination_policy(credentials,destinationName,policyregion,account_id):
    #destinationpolicy = {}
    session = boto3.session.Session()
    # Create CloudWatchLogs client
    cloudwatch_logs = session.client(
        service_name='logs',
        region_name=policyregion,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        # Update destination policy
        describe_destinations_response = cloudwatch_logs.describe_destinations(
            DestinationNamePrefix=destinationName   
        )
        #response = json.loads(describe_destinations_response)
        # length = len(describe_destinations_response['destinations'])
        # for i in range(length):
        print(describe_destinations_response['destinations'][0]['destinationName'])
        data = json.loads(describe_destinations_response['destinations'][0]['accessPolicy'])
        #print(data)
        #print(data["Statement"][0]["Principal"]["AWS"])
        data["Statement"][0]["Principal"]["AWS"].insert(0,account_id)
        #print(data["Statement"][0]["Principal"]["AWS"])
        #print(json.dumps(data))
        destinationpolicy = json.dumps(data)
        #print(describe_destinations_response)
    except botocore.exceptions.ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return destinationpolicy

def apply_updated_destination_policy(credentials,deployregion,destination,accesspolicy):
    destination_policy_updated = False
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
        # Update destination policy
        put_destination_policy_response = cloudwatch_logs.put_destination_policy(
            destinationName=destination,
            accessPolicy=accesspolicy
        )
        print(put_destination_policy_response['ResponseMetadata']['HTTPStatusCode'])
        if '200' in str(put_destination_policy_response['ResponseMetadata']['HTTPStatusCode']):
            destination_policy_updated = True
    except botocore.exceptions.ClientError as e:
        print("The request could not be completed:", e)
        raise
    finally:
        return destination_policy_updated
        
def lambda_handler(event,context):
    
    account_id = event['account_id']
    account_role = 'OrganizationAccountAccessRole'
    configregions = ["us-west-1","us-east-1","us-east-2","us-west-2"]
    regiondict = {'us-east-1':'east1', 'us-east-2':'east2', 'us-west-1':'west1', 'us-west-2':'west2'}
    kinesisstreamprefix = 'splunk-kinesis-stream'
    destinationNamePrefixarray = ['cloudwatch-lambda','cloudwatch-elasticsearch','cloudwatch-events','rdsosmetrics','rdslogs','cloudwatch','vpc-flow']
    policyregion = 'us-east-1'
    
    baselinesplunkstack = os.environ['BaselineSplunkStack']
    splunkregion = os.environ['BaselineSplunkRegion']

    is_splunk_stack_created = deploy_splunk(baselinesplunkstack,account_id,splunkregion)
    event['is_splunk_stack_created'] = is_splunk_stack_created
    print("Resources created successfully:"+ str(is_splunk_stack_created))
    
    KinesisAccount = os.environ['KinesisAccount']
    #Assume role of kinensis account to update the destination policy files
    credentials = assume_role(KinesisAccount, account_role)
    
    #Update destination policy in kinesis account adding the newly created account id
    destpolicyupdated = {}
    length = len(destinationNamePrefixarray)
    for i in range(length):
        filterName = destinationNamePrefixarray[i]
        destinationName = '{0}-{1}-{2}'.format(kinesisstreamprefix,destinationNamePrefixarray[i],regiondict[policyregion])
        #Create new access policy which includes the newly created account
        destinationpolicy = create_updated_destination_policy(credentials,destinationName,policyregion,account_id)
        print(destinationpolicy)
        for deployregion in configregions:
            destination =  '{0}-{1}-{2}'.format(kinesisstreamprefix,destinationNamePrefixarray[i],regiondict[deployregion])
            response = apply_updated_destination_policy(credentials,deployregion,destination,destinationpolicy)
            destpolicyupdated[destination] = response
    event['destpolicyupdated'] = destpolicyupdated
    print(event['destpolicyupdated'])
    #Describe destination policies in kinesis account    
    for deployregion in configregions:    
        for i in range(length):
            destinationName = '{0}-{1}-{2}'.format(kinesisstreamprefix,destinationNamePrefixarray[i],regiondict[deployregion])
            destinationpolicy = describe_destination_policy(credentials,destinationName,deployregion)
            print(destinationpolicy)
            
    return event