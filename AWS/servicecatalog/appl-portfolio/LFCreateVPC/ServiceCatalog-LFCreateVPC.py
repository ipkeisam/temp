import requests
import json
import boto3
import base64
import os
import time
from random import randint
from botocore.exceptions import ClientError

def sendTriggerLambdaResponse(message, context, responseStatus, responseData):
   
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': message['StackId'],
                    'RequestId': message['RequestId'],
                    'LogicalResourceId': message['LogicalResourceId'],
                    'Data': responseData}
    print('RESPONSE BODY:n' + json.dumps(responseBody))
    try:
        req = requests.put(message['ResponseURL'], data=json.dumps(responseBody))
        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return
    except requests.exceptions.RequestException as e:
        print(e)
        raise

def sendRequest(network_parameters,service_account,deployregion,numofsubnets):
    is_network_playbook_invoked = False
    url = os.environ['NETWORK_TOWER_URL']
    print(url)
    payload = {
        "extra_vars": {
            "account_profile": network_parameters['account_profile'],
            "aws_region": deployregion,
            "vpc_name": network_parameters['vpc_name'],
            "env": network_parameters['env'],
            "state": network_parameters['state'],
            #"ticket_number": 'FOR AWS NEW ACCOUNT ' + network_parameters['account_profile']
            "ticket_number": 'FOR NEW VPC CREATION IN THE REGION ' + deployregion + '  FOR THE ACCOUNT ' + network_parameters['account_profile'],
            "addtl_az": numofsubnets
        }
    } 

    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }
    print(payload)
    response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
    print(response.text)
    response_status = response.status_code
    if '201' in str(response_status):
        is_network_playbook_invoked = True
    return is_network_playbook_invoked

def get_secret(secretname,regionname):

    print(regionname)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionname
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretname
        )
    except ClientError as e:
        print("Exception raised:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret



def send_create_success_alert(account_name,account_id,vpc_name, region,env):
    snsregion = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=snsregion
            )
    try:
        message = '\n' + 'Please check the vpc with below details after few mins' + '\n' + '\n' +\
        'AWS account id: ' + account_id + '\n' + \
        'AWS account Name: ' + account_name + '\n' + \
        'vpc name: ' + vpc_name + '\n' + \
        'region: ' + region + '\n' + \
        'env: ' + env + '\n' 
        
        subject = "VPC creation request submitted successfully"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def send_delete_request_alert(account_name,account_id,vpc_name, region,env):
    snsregion = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=snsregion
            )
    try:
        message = '\n' + \
        'AWS account id: ' + account_id + '\n' + \
        'AWS account Name: ' + account_name + '\n' + \
        'vpc name: ' + vpc_name + '\n' + \
        'region: ' + region + '\n' + \
        'env: ' + env + '\n' 
        
        subject = "VPC delete request, please check with customer"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def send_create_failure_alert(account_name,account_id,vpc_name, region,env):
    snsregion = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=snsregion
            )
    try:
        message = '\n' + \
        'AWS account id: ' + account_id + '\n' + \
        'AWS account Name: ' + account_name + '\n' + \
        'vpc name: ' + vpc_name + '\n' + \
        'region: ' + region + '\n' + \
        'env: ' + env + '\n' 
        
        subject = "VPC creation failed, please check the logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def getVpcName(stackid):
   
   try:
        stackid_split_array = stackid.split('/')
        stackid_split_end_string = stackid_split_array[len(stackid_split_array)-1]
        end_string_split_array = stackid_split_end_string.split('-')
        vpc_con_string = end_string_split_array[len(end_string_split_array)-1]
        
        return 'vpc-'+vpc_con_string
   except:
          print('error in vpc name string formation')
          raise

def lambda_handler(event,context):

    network_parameters = {}
    is_network_playbook_invoked = False
    network_vpc_created = {}
    network_vpc_deleted = {}
    message = event['Records'][0]['Sns']['Message']
    data = json.loads(message)
    print(data)
    responseStatus = 'SUCCESS'
    responseData = {}

    #Retrieve parameters requird for Network module from State Machine event variable
    account_id = data['ResourceProperties']['account_id']
    print(account_id)
    orgclient = boto3.client('organizations')
    account_name =  orgclient.describe_account(AccountId=account_id).get('Account').get('Name').lower()
    print(account_name)
    acctags = orgclient.list_tags_for_resource(ResourceId= account_id)['Tags']
    
    env = ''
    for tag in acctags:
        if tag['Key'] == 'env-type':
            env = tag.get('Value').lower()
            break;
    print(env)
    
    region = data['ResourceProperties']['vpc_region']
    print(region)
    
    subnets = int(data['ResourceProperties']['number_of_subnets'])
    if region == 'us-west-1':
        subnets = 2
    print(subnets)
    subnet_mapping = {2:0, 3:1}
    numberofsubnets = subnet_mapping[subnets]

    #vpc_name = 'VPC-' + str(randint(10000,99999999))
    print('Stack Id: ' + data ['StackId'])
    vpc_name = getVpcName(data['StackId'])
    print(vpc_name)
    
    
    #temporary fix to set env type as prod instead of prd
    if env == "prd":
        env = "prod"
    
    if data['RequestType'] == "Create":
        
        print('Create VPC:  ' + vpc_name)
        
        network_parameters['state'] = 'present'
        
        network_parameters['account_profile'] = account_name
        network_parameters['vpc_name'] = vpc_name
        network_parameters['env'] = env
       
        #Secrets Manager will be setup in US-East-1 within master account
        secret_name = os.environ['NetworkServiceAccountCreds']
        region_name = os.environ['SecretsManagerRegionName']
        
        smresponse = get_secret(secret_name,region_name)
        smresponse_dict = json.loads(smresponse)
        service_account = smresponse_dict['IAMServiceAccount']
        
        # Invoke tower url
        #network_vpc_created.update({region:False})
        response = sendRequest(network_parameters,service_account,region,numberofsubnets)
        if response:
            send_create_success_alert(account_name,account_id,vpc_name, region,env)
        else: 
            responseStatus = 'Failure'
            send_create_failure_alert(account_name,account_id,vpc_name,region,env)
            
        network_vpc_created.update({region:response,'vpcname': vpc_name})  
        responseData['network_vpc_created'] = network_vpc_created
        
    else:
        # Handling the delete scenario - yet to integrate this feature with Ansible tower.
        print('Delete VPC:  ' + vpc_name)
        network_parameters['state'] = 'absent'
        network_vpc_deleted.update({region:False,'vpcname': vpc_name})
        send_delete_request_alert(account_name,account_id,vpc_name,region,env)
        responseData['network_vpc_deleted']  = network_vpc_deleted
        
    sendTriggerLambdaResponse(data, context, responseStatus, responseData)