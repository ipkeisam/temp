from __future__ import print_function
import os
import botocore
import boto3
import json
import requests

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
        
def sendAccountCreationStatus(data):
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
            Message=data
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def add_module_result(modulename,moduleResults,result,resultMessage):

    failed_module_result = {
        "module": modulename,
        "result": result,
        "resultMessage": resultMessage
    }
    moduleResults.append(failed_module_result)
    return moduleResults

def disable_account_scheduler():
    print("inside")
    response = ''
    schedulername = os.environ['ACCOUNT_SCHEDULER_NAME']
    schedulerregion = os.environ['ACCOUNT_SCHEDULER_REGION']
    session = boto3.session.Session()
    cwevent_client = session.client(
                service_name='events',
                region_name=schedulerregion
            )
    try:
        response = cwevent_client.disable_rule(
            Name=schedulername
        )
    except Exception as e:
        print("Error : {}".format(e))
    finally:
        return response

def lambda_handler(event,context):
    
    #print(event)
    requestid = event['requestid']

    accountname = event['account_name']
    accountemail = event['account_email']
    accounttype = event['accounttype']

    qadatatype = event['qadatatype']
    poc = event['poc']    
    remediationgroup = event['remediationgroup']

    usageid = event['usageid']
    environmenttype = event['environment_type']
    costcenter = event['cost_center']
    ppmcid = event['ppmcid']
    toc = event['toc']
    shutdownperiod = event['shutdown_period']
    expirydate = event['expiry_date']

    organizationunitname = event['organization_unit_name']
    networkregions = event['network_regions']

    accountid = event['account_id']

    result = 'success'
    resultMessage = "Account created successfully"

    #Secrets Manager will be setup in US-East-1 within master account
    secretname =  os.environ['ServiceNowCredentials']
    regionname = os.environ['SecretsManagerRegionName']

    #Get the service account to be used to submit Service Now tickets
    response = get_secret(secretname,regionname)
    response_dict = json.loads(response)
    service_account = response_dict['aws-compliance.webservice']
    moduleResults = []
	
    #Servicenow ticket for MFA setup
    if accountid != None:
       module_specific_parameters = get_snow_module_parameters("MFA_module")
       description = module_specific_parameters['description'].format(accountname.upper(),accountid)
       (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
       if isSNowTicketCreated:
           resultMessage = incidentNumber
       else:
           resultMessage = 'Service Now ticket creation failed.'
       moduleResults = add_module_result("MFA",moduleResults,'warn',resultMessage)

    towerjobstatus = ""
    if 'tower_job_status' in event:
        towerjobstatus = event['tower_job_status']
        #towerjobstatus = json.loads(towerjobstatus_str)
        if 'are_kms_keys_created' not in event:
            result = 'fail'
            resultMessage = 'Service Now ticket creation failed.'
            module_specific_parameters = get_snow_module_parameters("kms_module")
            description = module_specific_parameters['description'].format(accountname.upper(),accountid)
            (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
            if isSNowTicketCreated:
                resultMessage = incidentNumber
            moduleResults = add_module_result("KMS",moduleResults,result,resultMessage)

    iam_vertical_bar_job_id = ''
    iam_vertical_brr_job_id = ''
    iam_job_id = ''
    network_east1_job_id = ''
    network_west1_job_id = ''
    network_west2_job_id = ''
    
    if 'tower_job_ids' in event:
        tower_job_ids = event['tower_job_ids']
        if 'Broad Access Role' in str(tower_job_ids):
            iam_vertical_bar_job_id = tower_job_ids['IAM Vertical Access (Broad Access Role) Playbook Execution Status']
            print(iam_vertical_bar_job_id)
        if 'Broad Read Role' in str(tower_job_ids):
            iam_vertical_brr_job_id = tower_job_ids['IAM Vertical Access (Broad Read Role) Playbook Execution Status']
        if 'IAM Playbook' in str(tower_job_ids):
            iam_job_id = tower_job_ids['IAM Playbook Execution Status']
        if 'Network Playbook for us-east-1' in str(tower_job_ids):
            network_east1_job_id = tower_job_ids['Network Playbook for us-east-1 Execution Status']
        if 'Network Playbook for us-west-1' in str(tower_job_ids):
            network_west1_job_id = tower_job_ids['Network Playbook for us-west-1 Execution Status']
        if 'Network Playbook for us-west-2' in str(tower_job_ids):
            network_west2_job_id = tower_job_ids['Network Playbook for us-west-2 Execution Status']
            
    # Iterating over tower job status
    if  towerjobstatus:
        for tower_job, job_status in towerjobstatus.items(): 
            if "IAM Playbook Execution Status" in tower_job:
                if not job_status:
                    module_specific_parameters = get_snow_module_parameters("iam_module")
                    description = module_specific_parameters['description'].format(iam_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("IAM",moduleResults,result,resultMessage)
            elif "Network Playbook for us-east-1" in tower_job:
                if not job_status:
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    module_specific_parameters = get_snow_module_parameters("network_module")
                    description = module_specific_parameters['description'].format(network_east1_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("Network",moduleResults,result,resultMessage)
            elif "Network Playbook for us-west-1" in tower_job:
                if not job_status:
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    module_specific_parameters = get_snow_module_parameters("network_module")
                    description = module_specific_parameters['description'].format(network_west1_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("Network",moduleResults,result,resultMessage)
            elif "Network Playbook for us-west-2" in tower_job:
                if not job_status:
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    module_specific_parameters = get_snow_module_parameters("network_module")
                    description = module_specific_parameters['description'].format(network_west2_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("Network",moduleResults,result,resultMessage)
            elif "Broad Access Role" in tower_job:
                if not job_status:
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    module_specific_parameters = get_snow_module_parameters("iam_module")
                    description = module_specific_parameters['description'].format(iam_vertical_bar_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("IAM",moduleResults,result,resultMessage)
            elif "Broad Read Role" in tower_job:
                if not job_status:
                    result = 'fail'
                    resultMessage = 'Service Now ticket creation failed.'
                    module_specific_parameters = get_snow_module_parameters("iam_module")
                    description = module_specific_parameters['description'].format(iam_vertical_rar_job_id,accountname.upper(),accountid)
                    (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
                    if isSNowTicketCreated:
                        resultMessage = incidentNumber
                    moduleResults = add_module_result("IAM",moduleResults,result,resultMessage)
    else:
        module_specific_parameters = get_snow_module_parameters("iam_module")
        description = module_specific_parameters['description'].format('',accountname.upper(),accountid)
        (isSNowTicketCreated,incidentNumber) = submit_servicenow_ticket(module_specific_parameters,description,service_account)
        result = 'fail'
        resultMessage = 'Service Now ticket creation failed.'
        if isSNowTicketCreated:
            resultMessage = incidentNumber
        moduleResults = add_module_result("IAM",moduleResults,result,resultMessage)

    if result == 'fail':
        response = disable_account_scheduler()
    elif result == 'success':
        isDome9onboarded = False
        is_guardduty_enabled = False
        qualys_response = 'FAILURE'
        
        if 'QualysOutput' in event:
            qualys_enabled_json = event['QualysOutput']
            qualys_response = qualys_enabled_json['responseCode']
            
        if 'is_guardduty_enabled' in event:
            is_guardduty_enabled = event['is_guardduty_enabled']
            
        if 'isDome9onboarded' in event:
            isDome9onboarded = event['isDome9onboarded']
            
        if (not is_guardduty_enabled) or (qualys_response != 'SUCCESS') or (not isDome9onboarded):
            result = 'warn'

    if result == 'success':
        if 'is_okta_prod_provider_created' in event:
            if not event['is_okta_prod_provider_created']:
                result = 'warn'
    
    if result == 'success':
        if 'are_s3conformancepacks_created' in event:
            s3_conformance_pack_json = event['are_s3conformancepacks_created']
            for region_status in s3_conformance_pack_json.values():
                if not region_status:
                    result = 'warn'
                    break 
        if result == 'success':
            if 'are_mlconformancepacks_created' in event:
                ml_conformance_pack_json = event['are_mlconformancepacks_created']
                for region_status in ml_conformance_pack_json.values():
                    if not region_status:
                        result = 'warn'
                        break
        if result == 'success':
            if 'are_encrptionconformancepacks_created' in event:    
                encryption_conformance_pack_json = event['are_encrptionconformancepacks_created']
                for region_status in encryption_conformance_pack_json.values():
                    if not region_status:
                        result = 'warn'
                        break 
        if result == 'success':
            if 'are_paconformancepacks_created' in event:
                pa_conformance_pack_json = event['are_paconformancepacks_created']
                for region_status in pa_conformance_pack_json.values():
                    if not region_status:
                        result = 'warn'
                        break 

    result_mapping =  {'fail':'One or more of the critical modules failed ', 'warn':'One or more of governance modules did not succeed', 'success':'Account created successfully'}
    resultMessage = result_mapping[result]
    print(moduleResults)
    responseBody = {
        "requestId": requestid,
        "resourceProperties": {
            "accountId": int(accountid),
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
        "result": result,
        "resultMessage": resultMessage,
        "moduleResults": moduleResults
    }
    responseBody_json = json.dumps(responseBody)
    print(responseBody_json)
    sendAccountCreationStatus(responseBody_json)