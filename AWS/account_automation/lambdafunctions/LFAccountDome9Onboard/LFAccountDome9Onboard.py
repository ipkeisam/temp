# ======================================================================
#
# Program: dome9_onboard.py
# Programmer: CG
# Language: Python 3
# Date: 2020
# Description: Offical code that will be live in the 
# 			   AWS master account to onboard newly created AWS accounts 
#			   to Dome9 and associate to ruleset. 
#
# ======================================================================

import json
import time
import sys
import configparser
import string
from random import *
from time import sleep
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
import boto3
import botocore
import base64
from botocore.exceptions import ClientError
import os

# Assumes the role of the account in order to get credentials and pass to caller
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

# Get the secret from the account via credentials recived from the assumed_role function
def get_secret(secret, region, credentials):
    
    secret_name = secret
    region_name = region
    session = boto3.session.Session()
    
    #Create a boto3 session with the assumed role credentials 
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("Soteria-Dome9-onboarding::ERROR:The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("Soteria-Dome9-onboarding::ERROR:The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("Soteria-Dome9-onboarding::ERROR:The request had invalid params:", e)
    else: 
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
            print ("Soteria-Dome9-onboarding::INFO:Retrieved the Secrets")
            return json.loads(text_secret_data)

        else:
            binary_secret_data = get_secret_value_response['SecretBinary']

# Function to onboard AWS accounts to Dome9
def D9onboard(AWS_account_name, AWS_role_arn, secret_AWS_D9, D9_id, D9_key, ouHash):
    resp = False
    start = datetime.utcnow()

    url = "https://api.dome9.com/v2/CloudAccounts"

    # Make the API call to Dome9
    urldata = {"name": AWS_account_name, "credentials": {"arn": AWS_role_arn, "secret": secret_AWS_D9, "type": "RoleBased", "isReadOnly": "true"}, "fullProtection": "false", "organizationalUnitId": ouHash}
    headers = {'content-type': 'application/json'}

    # Calling the Dome9 API with all required info to add your AWS account.
    try:
        resp = requests.post(url, auth=HTTPBasicAuth(D9_id, D9_key), json=urldata, headers=headers)
        return resp
    except requests.exceptions.RequestException as e:
        print (e)
        raise e
    finally:
        return resp

# Extracts the IDs from Dome9: "Notification ID" & "Bundle ID"
def extract_ids(apiKey, apiSecret, identifier, url):
    resp = False
    headers = {'Accept': 'application/json'}
    try:
        r = requests.get(url, headers = headers, auth=(apiKey, apiSecret))
        c = r.content
        j = json.loads(c)

        # Finds the Notification ID & Bundle ID and passes it back to caller
        for item in j:
            if item["name"] == identifier:
                resp = item["id"]
                print ("Soteria-Dome9-onboarding::INFO:Retrieved the ID for ", identifer)
    except requests.exceptions.RequestException as e:
        print (e)
        raise e
    finally:
        return resp

# Gets the Cloud Accounts Dome9 ID in Dome9
def getAccountD9id(apiKey, apiSecret, account_id):
    resp = False
    url = 'https://api.dome9.com/v2/CloudAccounts/' + account_id
    headers = {'Accept': 'application/json'}

    # Making Dome9 API call to get the DOME9 ID for Cloud Account
    try:
        r = requests.get(url, headers = headers, auth=(apiKey, apiSecret))
        c = r.content
        j = json.loads(c)

        # Finds the ID of the account in Dome9 and passes it back to caller
        for item in j:
            if item == 'id':
                resp = j[item]
                print ("Soteria-Dome9-onboarding::INFO:Retrieved the Dome9 Account ID")
    except requests.exceptions.RequestException as e:
        print (e)
        raise e
    finally:
        return resp

# Creates the Dome9 Policy that connects a ruleset to a notifcation with an account
def createPolicy(apiKey, apiSecret, cloudAccountId, externalAccountId, bundleId, notificationId):
    resp = False
    url = "https://api.dome9.com/v2/Compliance/ContinuousCompliancePolicy"

    # Make the API call to Dome9
    urldata = {"cloudAccountId": cloudAccountId, "externalAccountId": externalAccountId, "cloudAccountType": "Aws", "bundleId": bundleId, "notificationIds": [notificationId]}
    headers = {'content-type': 'application/json'}

    try:
        resp = requests.post(url, auth=HTTPBasicAuth(apiKey, apiSecret), json=urldata, headers=headers)
    except requests.exceptions.RequestException as e:
        print (e)
        raise e
    finally:
        return resp

# Gets the OU list from Dome9 and finds the proper OU path for the new AWS account to live under in Dome9
def get_OU_hash(apikey, apisecret, account_name, sensitivity, manageability):
    
    resp = False
    url = 'https://api.dome9.com/v2/organizationalunit/GetFlatOrganizationalUnits'
    headers = {'Accept': 'application/json'}
    
    hash = []
    name = []
    path = []
    index = 0
    finalHash = []

    # Making Dome9 API call to get the DOME9 ID for Cloud Account
    try:
        r = requests.get(url, headers = headers, auth=(apikey, apisecret))
        c = r.content
        j = json.loads(c)
        
        # For loop gets all the ou level info into arrays for easy storage
        for orgs in j:
            index += 1
            hash.append(orgs['id'])
            name.append(orgs['name'].upper())
            stri = orgs['path'] + '.' + orgs['id'] # concat string in order to get full path
            pather = stri.split('.')
            del pather[0]
            path.append(pather)
            
            if 'UNASSIGNED' in orgs['name'].upper():
                unIndex = index-1
        
        # Can utilize the same length because it will always be one to one across each list
        length = len(hash)

        # fixing paths to have proper paths
        for j in range(length):
            for i in range(length):
                if hash[j] in path[i]:
                    path[i] = [sub.replace(hash[j], name[j]) for sub in path[i]]
        
        miss = 0
        
        if manageability is not "MANAGED":
            manageability = "UN-MANAGED"
        
        # if the environment is in Doundation, sandbox, or QA, then it is considered to be in Development
        if "FOUNDATION" in account_name or "SBX" in account_name or "QA" in account_name or "DEV" in account_name or "TST" in account_name or "TEST" in account_name:
            env = "NON-PRODUCTION"
        elif "PRD" in account_name or "PROD" in account_name:
            env = "PRODUCTION"
        else:
            env = "UNASSIGNED"

        # Check for Sensitivity
        if "NA" in sensitivity:
            sensitivity = ""
        else:
            sensitivity = "Sensitive "

        bucket = sensitivity + env
        # finding exact hash value that has the proper bucket path for account
        for k in range(length):
            if manageability in path[k] and bucket in path[k]:
                resp = hash[k]
                print ("Dome9onboarding::INFO: Account in Dome9 OU ---> ", path[k])
                break
            else:
                miss += 1
                if miss == length:
                    resp = hash[unIndex]
                    print ("Dome9onboarding::INFO: Account in Dome9 OU ---> ", path[k])

    except requests.exceptions.RequestException as e:
        print (e)
        raise e
    finally:
        return resp

def lambda_handler(event, context):

    print ("Soteria-Dome9-onboarding::INFO:Starting to onboard AWS account to Dome9...")

    # Variables
    event['isDome9onboarded'] = False
    isContinue = True
    keys = event.keys()

    # Checking to see if all the variables were passed to the lambda
    if 'account_id' in keys and 'account_name' in keys and 'qadatatype' in keys and 'accounttype' in keys:
        if not event['account_id'] or not event['account_name'] or not event['qadatatype'] or not event['accounttype']:
                isContinue = False
        else: 
            #Account role to get the secrets from a sub account
            account_role = 'OrganizationAccountAccessRole'

            # AWS Account id that holds the Secrets
            account_id = os.environ['Soteria_Prod_Account_ID']

            # Prod version
    
            region = "us-east-1"
            arn = "arn:aws:iam::" + event['account_id'] + ":role/Dome9-role"
            notifier = "Capital Group Security Foundations Notification Policy"
            api_safe = "prod/soteria/dome9api-prod"
            d9_secret_safe = "Prod/Soteria/AWS_D9_Secret"

            print ("Soteria-Dome9-onboarding::INFO:Assuming role to access Soteria...")
            credentials = assume_role(account_id, account_role)

            print ("Soteria-Dome9-onboarding::INFO:Attempting to get Secrets for onboarding...")
            Api = get_secret(api_safe, region, credentials)
            AWS_D9_secret = get_secret(d9_secret_safe, region, credentials)

            ######
            # Trying to get the proper OU to put the account under for Dome9
            print ("Soteria-Dome9-onboarding::INFO:Trying to get the OU list...")
            ouResponse = get_OU_hash(Api["apiKey"], Api["apiSecret"], event['account_name'].upper(), event['qadatatype'].upper(), event['accounttype'].upper())
        
            # Check to see if the function was successfull or not
            if ouResponse == False:
                print ("Soteria-Dome9-onboarding::ERROR:Extraction of OU bucket for account failed...")
                isContinue = False
            
            # Call to Onboard AWS account to Dome9
            print ("Soteria-Dome9-onboarding::INFO:Trying to onboard AWS account...")
            counter = 20
            check_d9_on = True
            while check_d9_on is True and isContinue is True:
                counter -=1
                check_d9_on = False
                feedback = D9onboard(event['account_name'], arn, AWS_D9_secret["Secret"], Api["apiKey"], Api["apiSecret"], ouResponse)
                if (counter > 0):
                    if (feedback == False):
                        print("Soteria-Dome9-onboarding::ERROR: Attempt #", counter, "AWS account couldn't be onboarded to Dome9...Trying again")
                        check_d9_on = True
                        time.sleep(15)
                    elif ("already protected by Dome9" in feedback.text):
                        print("Soteria-Dome9-onboarding::ERROR: AWS account has already been onboarded to Dome9")
                        isContinue = False
                        break
                    elif(feedback.status_code == 400):
                        print ("Soteria-Dome9-onboarding::ERROR: Attempt #", counter, "Error in onboarding, trying again")
                        check_d9_on = True
                        time.sleep(15)
                    else:
                        print("Soteria-Dome9-onboarding::INFO:Successfully Onboarded account...")
                        isContinue = True
                        break
                if (counter == 0):
                    print ("Soteria-Dome9-onboarding::ERROR: Could not onboard AWS account to Dome9 after 20 retries...")
                    isContinue = False

            # IF something went wrong with the call like call interuption - then failure has occured
            if isContinue is False:
                print ("Soteria-Dome9-onboarding::ERROR:Dome9 onboarding failed, please contact Soteria Engineers for assistance.")
            elif (feedback == False):
                print("Soteria-Dome9-onboarding::ERROR:Dome9 onboarding has failed, please contact Dome9 Admins to onboard manually...")
                isContinue = False
            elif (feedback.status_code >= 200 and feedback.status_code < 205):

                print ("Soteria-Dome9-onboarding::INFO:Onboarding of AWS account to Dome9 Successful...")

                print ("Soteria-Dome9-onboarding::INFO:Trying to pull the Dome9 Notification ID, Cloud Account ID, & ruleset ID...")
                # Getting the Notification ID for where to send logs for Scans
                notification_id = extract_ids(Api["apiKey"], Api["apiSecret"], notifier, 'https://api.dome9.com/v2/Compliance/ContinuousComplianceNotification')
                if (notification_id == False):
                    print ("Soteria-Dome9-onboarding::ERROR:Extraction of Dome9 Notification ID Failed...")
                    isContinue = False
            
                # Getting the Dome9 Account ID for the Cloud Account
                aws_d9_id = getAccountD9id(Api["apiKey"], Api["apiSecret"], event['account_id'])
                if (aws_d9_id == False):
                    print ("Soteria-Dome9-onboarding::ERROR:Extraction of Dome9 Cloud Account ID in Dome9 Failed...")
                    isContinue = False

                # Getting the rulesets to associate with the account when scanning
                bundle_id = extract_ids(Api["apiKey"], Api["apiSecret"], 'CG-AWS-SO', 'https://api.dome9.com/v2/CompliancePolicy')
                if (bundle_id == False):
                    print ("Soteria-Dome9-onboarding::ERROR:Extraction of Dome9 Ruleset ID Failed...")
                    isContinue = False

                if (isContinue == True):

                    print ("Soteria-Dome9-onboarding::INFO:Extraction of the Dome9 Notification ID, Cloud Account ID, & ruleset ID Successful...")

                    # Cretating the Policy to associate ruleset + notification to AWS account
                    print ("Soteria-Dome9-onboarding::INFO:Attempting to create Policy to associate new onboarded cloud account to ruleset for scanning...")
                    result = createPolicy(Api["apiKey"], Api["apiSecret"], aws_d9_id, event['account_id'], bundle_id, notification_id)

                    if (result == False):
                        print ("Soteria-Dome9-onboarding::ERROR:Creation of Dome9 policy for new account has Failed...")
                        isContinue = False
                    if (result.status_code >= 200 and result.status_code < 205):
                        print ("Soteria-Dome9-onboarding::SUCCESS:AWS account has been onboarded to Dome9 and policy has been associated to account!")
                    else:
                        print ("Soteria-Dome9-onboarding::ERROR:Creation of policy for new account has Failed...")
                        isContinue = False
            else:
                print ("Soteria-Dome9-onboarding::ERROR:AWS account couldn't be onboarded to Dome9")
                isContinue = False
    else:
        print ("Soteria-Dome9-onboarding::ERROR:AWS account couldn't be onboarded to Dome9, duue to missing event Variables")
        isContinue = False

    event['isDome9onboarded'] = isContinue

    print ("Soteria-Dome9-onboarding::INFO:Dome9 onboarding lambda has finished...")

    return event