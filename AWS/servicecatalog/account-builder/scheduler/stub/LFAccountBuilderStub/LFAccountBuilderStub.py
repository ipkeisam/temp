from __future__ import print_function
import json
import requests
from random import randrange
import os
import boto3
import botocore
import logging
import random
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

def get_secret(secretname,regionname):

    print(secretname)
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
    except botocore.exceptions.ClientError as e:
        print("Exception raised:", e)
        raise
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret
        
def checkInputParameters(messagedata):

    all_parameters_available = True
    try:
        organization_unit_name = messagedata['ResourceProperties']['organizationUnitName']
        accountname = messagedata['ResourceProperties']['accountName']
        accounttype = messagedata['ResourceProperties']['accountType']
        remediationgroup = messagedata['ResourceProperties']['remediationGroup']
        environmenttype = messagedata['ResourceProperties']['environmentType']
        costcenter = messagedata['ResourceProperties']['costCenter']
        ppmcid = messagedata['ResourceProperties']['ppmcID']
        usageid = messagedata['ResourceProperties']['usageID']
        qadatatype = messagedata['ResourceProperties']['qaDataType']
        poc = messagedata['ResourceProperties']['poc']
        toc = messagedata['ResourceProperties']['toc']
        shutDownPeriod = messagedata['ResourceProperties']['shutDownPeriod']
        expiryDate = messagedata['ResourceProperties']['expiryDate']
        networkRegions = messagedata['ResourceProperties']['networkRegions']

    except Exception as e:
        print("one or more parameters missing:", e)
        all_parameters_available = False
        raise
    finally:
        return all_parameters_available

def sendAccountCreationStatus(data):
    region = os.environ['ACCOUNT_STATUS_SNS_REGION']
    topicArn = os.environ['ACCOUNT_STATUS_SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=data
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def send_create_failure_alert(messagedata,account_name,environment):
    region = os.environ['ACCOUNT_ALERT_SNS_REGION']
    topicArn = os.environ['ACCOUNT_ALERT_SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        message = '\n' + \
        'AWS account name: ' + account_name + '\n' + \
        'Environment: ' + environment

        subject = "New Account creation failed, please check the logs"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))
        raise

def send_delete_request_alert(account_id,account_name,environment_type,poc):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        message = '\n' + \
        'AWS Account ID: ' + account_id + '\n' + \
        'AWS Acount Name: ' + account_name + '\n' + \
        'Environment Type: ' +  environment_type + '\n' + \
        'Account POC: ' + poc

        subject = "AWS account delete request initiated, please take appropriate action"
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))
        raise

def getSQSMessage():

    response = ''
    sqsurl =  os.environ['SQSURL']
    rgionname = os.environ['SQSRegionName']
    message_extraction_successful = False
    messages = ''
    session = boto3.session.Session()
    sqs_client = session.client(
                service_name='sqs',
                region_name=rgionname
            )
    try:
        response = sqs_client.receive_message(
            QueueUrl=sqsurl,
            MaxNumberOfMessages=1,
        )
        if response['Messages']:
            messages = response['Messages']
            print(messages)
            message_extraction_successful = True
    except Exception as e:
        print("Error retrieving messages. Error : {}".format(e))
    finally:
        print(message_extraction_successful)
        return messages,message_extraction_successful

def deleteSQSMessage(receipthandle):

    response = ''
    sqsurl =  os.environ['SQSURL']
    rgionname = os.environ['SQSRegionName']
    message_deletion_successful = False
    session = boto3.session.Session()
    sqs_client = session.client(
                service_name='sqs',
                region_name=rgionname
            )
    try:
        response = sqs_client.delete_message(
            QueueUrl=sqsurl,
            ReceiptHandle=receipthandle,
        )
        print(response)
        message_deletion_successful = True
    except Exception as e:
        print("Error setting default ebs encryption. Error : {}".format(e))
        raise
    finally:
        print(message_deletion_successful)
        return response,message_deletion_successful

def submit_servicenow_ticket(module_specific_parameters,description,service_account):
    is_servicenow_ticket_submitted = False
    url = os.environ['SNOW_API_URL']
    
    assignment_group = module_specific_parameters['assignment_group']
    caller_id = module_specific_parameters['caller_id']
    business_service = module_specific_parameters['business_service']
    category = module_specific_parameters['category']
    contact_type = module_specific_parameters['contact_type']
    short_description = module_specific_parameters['short_description']
    impact = module_specific_parameters['impact']
    urgency = module_specific_parameters['urgency']
    #description = module_specific_parameters['description']

    servicenow_params = {
			"caller_id":caller_id,
			"business_service":business_service,
			"category":category,
			"contact_type":contact_type,
			"assignment_group":assignment_group,
			"short_description":short_description,
			"impact":int(impact),
			"urgency":int(urgency),
			"description":description
    }
    
    headers = {
        'content-type': "application/json",
        'authorization': "Basic " + service_account,
        'cache-control': "no-cache"
    }
    IncidentNumber = ''
    response = requests.request("POST", url, data=json.dumps(servicenow_params), headers=headers)
    print(response)
    print(response.text)
    if '201' in str(response.status_code):
        is_servicenow_ticket_submitted = True
        json_response_dict = json.loads(response.text)
        IncidentNumber = json_response_dict['result']['IncidentNumber']
    print(IncidentNumber)
    return is_servicenow_ticket_submitted,IncidentNumber

def get_snow_module_parameters(modulename):

    sourcebucket = os.environ['SOURCE_BUCKET']
    filename = os.environ['SNOW_PARAMETERS_FILE']
    s3 = boto3.resource('s3','us-east-1')
    module_specific_parameters = {}
    try:
        obj = s3.Object(sourcebucket,filename)
        module_parameters = json.loads(obj.get()['Body'].read().decode('utf-8'))
        module_specific_parameters = module_parameters[modulename]
    except botocore.exceptions.ClientError as e:
        print("Error accessing the source bucket. Error : {}".format(e))
    finally:
        return module_specific_parameters

def account_name_only_letters(applicationname,environmenttype,qadatatype):
  
    # remove incorrect postfix to appl name
    result = applicationname
    if applicationname.endswith("DEV"): 
        result = re.sub("DEV", '', applicationname)
    elif applicationname.endswith("QA"): 
        result = re.sub("QA", '', applicationname)
    elif applicationname.endswith("PRD"): 
        result = re.sub("PRD", '', applicationname)
    elif applicationname.endswith("PROD"): 
        result = re.sub("PROD", '', applicationname)
    
    if result.startswith("AWS-"): 
        result = re.sub("AWS-", '', result)

    # function to remove characters 
    # which are not alphabets using re 
    getVals = list([val for val in result 
                if val.isalpha()]) 
    
    appname = "".join(getVals)
    if environmenttype == 'DEV' and qadatatype == 'sensitive':
        environmenttype = 'QA'

    accountname = 'AWS-' + appname + '-' + environmenttype 
    return accountname,environmenttype
    
def lambda_handler(event,context):

    responseData = {}
    messagedata = ''
    environmenttype = "NA"
    accountname = "NA"
    (messages,message_extraction_successful) = getSQSMessage()

    if message_extraction_successful:
        receipthandle = messages[0]['ReceiptHandle']
        requestid = messages[0]['MessageId']
        event['requestid'] = requestid
        print("request id:" + event['requestid'])

        body = messages[0]['Body']
        #print(body)
        bodydata = json.loads(body)
        #print(bodydata)
        message = bodydata["Message"]
        #print(message)
        messagedata = json.loads(message)
        #print(messagedata)

        all_parameters_available = checkInputParameters(messagedata)
        if all_parameters_available:

            qadatatype = messagedata['ResourceProperties']['qaDataType']
            environmenttype = messagedata['ResourceProperties']['environmentType'] 
            usageid = messagedata['ResourceProperties']['usageID'].upper()
            accountname = messagedata['ResourceProperties']['accountName'].upper()
            
            userinitials = "na"
            if "userInitials" in message:
                userinitials = messagedata['ResourceProperties']['userInitials']

            if "SERVICENOW" in message:
                (accountname,environmenttype) = account_name_only_letters(accountname,environmenttype,qadatatype)
            
            print(accountname)
            account_id = str(randrange(10**11, 10**12))
            accounttype = messagedata['ResourceProperties']['accountType']
            accountemail = accountname.lower() + "@capgroup.com"

            remediationgroup = messagedata['ResourceProperties']['remediationGroup']
            costcenter = messagedata['ResourceProperties']['costCenter']
            ppmcid = messagedata['ResourceProperties']['ppmcID']
            toc = messagedata['ResourceProperties']['toc']
            shutdownperiod = messagedata['ResourceProperties']['shutDownPeriod']
            expirydate = messagedata['ResourceProperties']['expiryDate']

            poc = messagedata['ResourceProperties']['poc']
            organizationunitname = messagedata['ResourceProperties']['organizationUnitName']

            networkregions = messagedata['ResourceProperties']['networkRegions'].split(",")

            #Secrets Manager will be setup in US-East-1 within master account
            secretname =  os.environ['ServiceNowCredentials']
            regionname = os.environ['SecretsManagerRegionName']
        
            #Get the service account to be used to submit Service Now tickets
            response = get_secret(secretname,regionname)
            response_dict = json.loads(response)
            service_account = response_dict['aws-compliance.webservice']
    
            moduleResults = []
            try:
                #Delete the message from the queue
                (response,message_deletion_successful) = deleteSQSMessage(receipthandle)
                print(message_deletion_successful)

                if messagedata['RequestType'] == "Create":

                    #resultRandom = random.choice(['success','fail','warn'])
                    resultRandom = random.choice(['fail','warn'])
                    if resultRandom == 'success':
                        resultMessageRandom = "Account created successfully"
                    elif resultRandom == 'fail':
                        module_specific_parameters = get_snow_module_parameters("iam_module")
                        description = module_specific_parameters['description'].format(str(randrange(10**11, 10**12)),"TEST-ACCOUNT-DEV",account_id)
                        (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                        result = 'fail'
                        resultMessageRandom = 'Service Now ticket creation failed.'
                        if isSNowTicketCreated:
                            resultMessageRandom = incidentNumber
                        moduleResults = add_module_result("IAM",moduleResults,result,resultMessage)
                        #resultMessageRandom = random.choice(['Some or all of IAM users/roles/groups did not get created successfully.','Some or all of IAM users/roles/groups did not get created successfully.'])
                    else:
                        resultMessageRandom = random.choice(['Network VPC within the account may not have been provisioned for one or more regions.','IAM Vertical access (broad access or broad read or both) may not have been setup correctly for the account.','One or more security modules did not get enabled for the account.','Okta federation may not be setup correctly for the account.'])
                    
                    responseBody = {
                        "requestId": requestid,
                        "resourceProperties": {
                            "accountId": int(account_id),
                            "accountName": accountname,
                            "accountType": accounttype,
                            "remediationGroup": remediationgroup,
                            "organizationUnitName": organizationunitname,
                            "environmentType": environmenttype,
                            "qaDataType": qadatatype,
                            "networkRegions": networkregions,
                            "poc": poc,
                            "costCenter": costcenter,
                            "ppmcID": ppmcid,
                            "usageID": usageid,
                            "expiryDate": expirydate,
                            "shutDownPeriod": shutdownperiod,
                            "toc": toc
                        },
                        "result": resultRandom,
                        "resultMessage": resultMessageRandom,
                        "moduleResults": moduleResults
                    }
                    responseBody_json = json.dumps(responseBody)
                    sendAccountCreationStatus(responseBody_json)

                else:
                    #The account is being deleted, send notification to PDS team there is request to delete account
                    log.info("send notification for account deletion")
                    send_delete_request_alert(account_id,accountname,environmenttype,poc)
            except Exception as e:
                print('Signaling account creation failure:',e)
                send_create_failure_alert(messagedata,accountname,environmenttype)
        else:
            print("not all parameters were passed correctly")
            send_create_failure_alert(messagedata,accountname,environmenttype)
    else:
        print('Message extraction unsuccessful.')