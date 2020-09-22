import boto3, botocore, logging
import time
import json
import requests
import os
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

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

def create_account(acctName,emailAddress):
    is_account_created = False
    newAccountId = "NA"
    client = boto3.client('organizations')
    try:
        acctResponse = client.create_account(
            Email=emailAddress,
            AccountName=acctName 
        )
        acctStatusID = acctResponse['CreateAccountStatus']['Id']
        log.info(acctStatusID)

        while True:
            createStatus = client.describe_create_account_status(
                CreateAccountRequestId=acctStatusID
            )
            if str(createStatus['CreateAccountStatus']['State']) == 'FAILED':
                break
            elif str(createStatus['CreateAccountStatus']['State']) == 'SUCCEEDED':
                newAccountId = str(createStatus['CreateAccountStatus']['AccountId'])
                is_account_created = True
                break
            time.sleep(10)
    except Exception as ex:
        log.info(ex)
        raise
    finally:
        return (is_account_created,newAccountId)

def tagAccount(accountid,tagdict):
    is_account_tagged = False
    client = boto3.client('organizations')
    mandatory_tags = {
                    "usage-id":tagdict['usageid'],
                    "poc":tagdict['poc'],
                    "account-type":tagdict['accounttype'],
                    "ppmc-id":tagdict['ppmcid'],
                    "cost-center":tagdict['costcenter'],
                    "remediation-group":tagdict['remediationgroup'],
                    "env-type":tagdict['envtype'],
                    "exp-date":tagdict['expirydate'],
                    "toc":tagdict['toc'],
                    "sd-period":tagdict['shutdownperiod'],
                    "account-name":tagdict['accountname'],
                    "sensitive-nonprod":tagdict['qadatatype'],
                    "auto-tag":tagdict['autotag']
    }
    try:
        response = client.tag_resource(
            ResourceId=accountid,
            Tags=[{'Key': str(k), 'Value': str(v)} for k, v in mandatory_tags.items()]
        )
        is_account_tagged = True
        log.info(response)
    except Exception as ex:
        log.info(ex)
        raise
    finally:
        return is_account_tagged

def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            print("before assume role")
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

def createBudget(account_id,credentials,budgetName,budgetLimit,notificationEmail,alertThreshold1,alertThreshold2,alertThreshold3):
    is_account_budget_created = False
    client = boto3.client('budgets',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])

    floatalertThreshold1 = float(alertThreshold1)
    if alertThreshold2.lower() == "na":
        alertThreshold2 = "40000000000"
    floatalertThreshold2 = float(alertThreshold2)

    if alertThreshold3.lower() == "na":
        alertThreshold3 = "40000000000"
    floatalertThreshold3 = float(alertThreshold3)

    try:
        response = client.create_budget(
            AccountId=account_id,
            Budget={
                'BudgetName': budgetName,
                'BudgetLimit': {
                    'Amount': budgetLimit,
                    'Unit': 'dollars'
                },
                'TimeUnit': 'MONTHLY',
                'TimePeriod': {
                    'Start': '1225864800',
                    'End': '3706473600'
                },
                'BudgetType': 'COST'
            },
            NotificationsWithSubscribers=[
                {
                    'Notification': {
                        'NotificationType': 'ACTUAL',
                        'ComparisonOperator': 'GREATER_THAN',
                        'Threshold': floatalertThreshold1,
                        'ThresholdType': 'PERCENTAGE'
                    },
                    'Subscribers': [
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': notificationEmail
                        },
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': 'aws-compliance-change-alerts@capgroup.com'
                        }
                    ]
                },
                {
                    'Notification': {
                        'NotificationType': 'ACTUAL',
                        'ComparisonOperator': 'GREATER_THAN',
                        'Threshold': floatalertThreshold2,
                        'ThresholdType': 'PERCENTAGE'
                    },
                    'Subscribers': [
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': notificationEmail
                        },
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': 'aws-compliance-change-alerts@capgroup.com'
                        }
                    ]
                },
                {
                    'Notification': {
                        'NotificationType': 'ACTUAL',
                        'ComparisonOperator': 'GREATER_THAN',
                        'Threshold': floatalertThreshold3,
                        'ThresholdType': 'PERCENTAGE'
                    },
                    'Subscribers': [
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': notificationEmail
                        },
                        {
                            'SubscriptionType': 'EMAIL',
                            'Address': 'aws-compliance-change-alerts@capgroup.com'
                        }
                    ]
                }
            ]
        )
        is_account_budget_created = True
        log.info(response)
    except Exception as ex:
        log.info(ex)
        raise
    finally:
        return is_account_budget_created

def invokeStepFunction(responseData):
    
    client = boto3.client('stepfunctions')
    response = client.start_execution(
        stateMachineArn='arn:aws:states:us-east-1:848721808596:stateMachine:AccountVending-StateMachine',
        input= json.dumps(responseData)
    )

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

def send_create_failure_alert(messagedata,account_name,environment):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
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
    # which are not alphabets
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
    #print(event)
    (messages,message_extraction_successful) = getSQSMessage()

    if message_extraction_successful:
        receipthandle = messages[0]['ReceiptHandle']
        messageId = messages[0]['MessageId']
        event['requestid'] = messageId
        print("request id:" + event['requestid'])

        body = messages[0]['Body']
        #print(body)
        bodydata = json.loads(body)
        #print(bodydata)
        message = bodydata["Message"]
        #print(message)
        messagedata = json.loads(message)
        #print(messagedata)
        print("request id:" + event['requestid'])

        all_parameters_available = checkInputParameters(messagedata)
        if all_parameters_available:
            qadatatype = messagedata['ResourceProperties']['qaDataType']
            environmenttype = messagedata['ResourceProperties']['environmentType'] 
            usageid = messagedata['ResourceProperties']['usageID'].upper()
            accountname = messagedata['ResourceProperties']['accountName'].upper()
            
            if "SERVICENOW" in message:
                (accountname,environmenttype) = account_name_only_letters(accountname,environmenttype,qadatatype)

            autotag = "true"
            if "autoTag" in message:
                autotag = messagedata['ResourceProperties']['autoTag']
            
            userinitials = "na"
            if "userInitials" in message:
                userinitials = messagedata['ResourceProperties']['userInitials']

            accounttype = messagedata['ResourceProperties']['accountType']

            if environmenttype == "DEV":
                accounttype = "unmanaged"

            remediationgroup = messagedata['ResourceProperties']['remediationGroup']
            costcenter = messagedata['ResourceProperties']['costCenter']
            ppmcid = messagedata['ResourceProperties']['ppmcID']
            
            poc = messagedata['ResourceProperties']['poc']
            toc = messagedata['ResourceProperties']['toc']
            shutDownPeriod = messagedata['ResourceProperties']['shutDownPeriod']
            expiryDate = messagedata['ResourceProperties']['expiryDate']
            organization_unit_name = messagedata['ResourceProperties']['organizationUnitName']
            networkRegions = messagedata['ResourceProperties']['networkRegions'].split(",")
            accountemail = accountname.lower() + "@capgroup.com"
            
            event['user_initials'] = userinitials
            event['network_regions'] = networkRegions

            event['environment_type'] = environmenttype
            event['account_name'] = accountname
            event['account_email'] = accountemail

            event['qadatatype'] = qadatatype
            event['usageid'] = usageid
            event['accounttype'] = accounttype
            event['remediationgroup'] = remediationgroup
            event['cost_center'] = costcenter
            event['ppmcid'] = ppmcid
            event['poc'] = poc
            event['toc'] = toc
            event['shutdown_period'] = shutDownPeriod
            event['expiry_date'] = expiryDate
            
            event['organization_unit_name'] = organization_unit_name

            print(event)
            try:
                #Delete the message from the queue
                (response,message_deletion_successful) = deleteSQSMessage(receipthandle)
                print(message_deletion_successful)

                account_role = 'OrganizationAccountAccessRole'
                org_client = boto3.client('organizations')
                if messagedata['RequestType'] == "Create":
                    try:
                        list_roots_response = org_client.list_roots()
                        log.info(list_roots_response)
                        root_id = list_roots_response['Roots'][0]['Id']
                    except:
                        root_id = "Error"

                    event['is_valid_account'] = False
                    responseData['AccountLevelTaggingApplied'] = "False"
                    responseData['AccountId'] = 'False'
                    responseStatus = 'FAILED'

                    if root_id  != "Error":
                        (is_account_created,account_id) = create_account(accountname,accountemail)
                        event['account_id'] = account_id        
                        if is_account_created:
                            event['is_valid_account'] = True
                            responseData['AccountId'] = account_id
                            responseStatus = 'SUCCESS'
                            try:

                                #Tag the account with the mandatory values
                                tagdict = {'autotag': autotag, 'expirydate':expiryDate, 'shutdownperiod':shutDownPeriod, 'toc':toc, 'qadatatype':qadatatype, 'accountname':accountname, 'poc':poc, 'costcenter':costcenter, 'envtype':environmenttype, 'accounttype': accounttype, 'ppmcid':ppmcid, 'usageid':usageid, 'remediationgroup':remediationgroup}
                                tag_response = tagAccount(account_id,tagdict)
                                responseData['AccountLevelTaggingApplied'] = "True"

                                if "developer" in accountname.lower():
                                    #Setup budget alerts for the developer
                                    budgetName = messagedata['ResourceProperties']['budgetName']
                                    budgetLimit = messagedata['ResourceProperties']['budgetLimit']
                                    notificationEmail = messagedata['ResourceProperties']['notificationEmail']
                                    alertThreshold1 = messagedata['ResourceProperties']['alertThreshold1']
                                    alertThreshold2 = messagedata['ResourceProperties']['alertThreshold2']
                                    alertThreshold3 = messagedata['ResourceProperties']['alertThreshold3']
                                    account_role = 'OrganizationAccountAccessRole'
                                    credentials = assume_role(account_id, account_role)
                                    budegt_response = createBudget(account_id,credentials,budgetName,budgetLimit,notificationEmail,alertThreshold1,alertThreshold2,alertThreshold3)
                            except Exception as ex:
                                log.info(ex)
                                raise
                            finally:
                                log.info("invoke step function")
                                response = invokeStepFunction(event)
                                #sendResponse(event, context, responseStatus, responseData)
                        else:
                            log.info("Cannot create new account.")
                            send_create_failure_alert(messagedata,accountname,environmenttype)
                            #sendResponse(event, context, responseStatus, responseData)
                    else:
                        log.info("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
                        send_create_failure_alert(messagedata,accountname,environmenttype)
                        #sendResponse(event, context, responseStatus, responseData)
                else:
                    #The account is being deleted, send notification to PDS team there is request to delete account
                    log.info("send notification for account deletion")
                    send_delete_request_alert(account_id,accountname,environmenttype,poc)
                    #responseData['accont_delete_request_sent'] = True
                    #responseStatus = 'SUCCESS'
                    #sendResponse(event, context, responseStatus, responseData)
            except Exception as e:
                print('Signaling account creation failure:',e)
                send_create_failure_alert(messagedata,accountname,environmenttype)
                #responseStatus = 'FAILED'
        else:
            print("not all parameters were passed correctly")
            send_create_failure_alert(messagedata,accountname,environmenttype)
    else:
        print('Message extraction unsuccessful.')