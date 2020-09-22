import boto3, botocore, logging
import time
import json
import requests
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

def get_ou_name_id(root_id,organization_unit_name,environmenttype):
    ou_client = boto3.client('organizations')
    list_of_OU_ids = []
    list_of_OU_names = []
    ou_name_to_id = {}
    
    list_of_OUs_response = ou_client.list_organizational_units_for_parent(ParentId=root_id)
    print(list_of_OUs_response)
    
    for i in list_of_OUs_response['OrganizationalUnits']:
        list_of_OU_ids.append(i['Id'])
        list_of_OU_names.append(i['Name'])

    print(list_of_OU_ids)
    print(list_of_OU_names)

    for i in range(len(list_of_OU_names)):
        ou_name_to_id[list_of_OU_names[i]] = list_of_OU_ids[i]
      
    print(ou_name_to_id)
    print(organization_unit_name)
    organization_unit_id = ou_name_to_id[organization_unit_name]
    print(organization_unit_id)

    if(environmenttype == "NA"):
        return organization_unit_id
        
    else:
        print(environmenttype)
        list_of_OU_ids = []
        list_of_OU_names = []
        ou_name_to_id = {}
        list_of_OUs_response = ou_client.list_organizational_units_for_parent(ParentId=organization_unit_id)
        
        for i in list_of_OUs_response['OrganizationalUnits']:
            list_of_OU_ids.append(i['Id'])
            list_of_OU_names.append(i['Name'])
            
        for i in range(len(list_of_OU_names)):
            ou_name_to_id[list_of_OU_names[i]] = list_of_OU_ids[i]
            
        print(ou_name_to_id)
        print(organization_unit_name)
        organization_unit_id = ou_name_to_id[environmenttype]
        
        return organization_unit_id
        #get_ou_name_id(organization_unit_id,environmenttype,"FALSE")

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
                    "env-type":tagdict['envtype']
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

def invokeStepFunction(responseData):
    
    client = boto3.client('stepfunctions')
    response = client.start_execution(
        stateMachineArn='arn:aws:states:us-east-1:848721808596:stateMachine:AccountVending-StateMachine',
        input= json.dumps(responseData)
    )
    
def lambda_handler(event,context):
    organization_unit_name = event['ResourceProperties']['organizationunitname']
    #accountemail = event['ResourceProperties']['accountemail']
    accountname = event['ResourceProperties']['accountname']
    accountemail = accountname.lower() + "@capgroup.com"

    accounttype = event['ResourceProperties']['accounttype']
    remediationgroup = event['ResourceProperties']['remediationgroup']
    environmenttype = event['ResourceProperties']['environmenttype']
    costcenter = event['ResourceProperties']['costcenter']
    ppmcid = event['ResourceProperties']['ppmcid']
    usageid = event['ResourceProperties']['usageid']
    qadatatype = event['ResourceProperties']['qadatatype']
    poc = event['ResourceProperties']['poc']

    event['vpccidrblocke1'] = event['ResourceProperties']['vpccidrblocke1']
    event['vpccidrblockw1'] = event['ResourceProperties']['vpccidrblockw1']
    
    event['environment_type'] = environmenttype
    event['account_name'] = accountname
    event['account_email'] = accountemail

    event['qadatatype'] = qadatatype
    event['usageid'] = usageid
    event['accounttype'] = accounttype
    event['remediationgroup'] = remediationgroup


    account_role = 'OrganizationAccountAccessRole'
    org_client = boto3.client('organizations')
    responseData = {}   

    try:
        list_roots_response = org_client.list_roots()
        log.info(list_roots_response)
        root_id = list_roots_response['Roots'][0]['Id']
    except:
        root_id = "Error"

    event['is_valid_account'] = False
    responseData['AccountMovedToOU'] = "False"
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
                organization_unit_id = get_ou_name_id(root_id,organization_unit_name,environmenttype)
                move_response = org_client.move_account(AccountId=account_id,SourceParentId=root_id,DestinationParentId=organization_unit_id)

                #Tag the account with the mandatory values
                tagdict = {'poc':poc, 'costcenter':costcenter, 'envtype':environmenttype, 'accounttype': accounttype, 'ppmcid':ppmcid, 'usageid':usageid, 'remediationgroup':remediationgroup}
                tag_response = tagAccount(account_id,tagdict)
                responseData['AccountMovedToOU'] = "True"
            except Exception as ex:
                log.info(ex)
                responseData['AccountMovedToOU'] = "False"
                raise
            finally:
                response = invokeStepFunction(event)
                sendResponse(event, context, responseStatus, responseData)
        else:
            sendResponse(event, context, responseStatus, responseData)
    else:
        log.info("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
        sendResponse(event, context, responseStatus, responseData)