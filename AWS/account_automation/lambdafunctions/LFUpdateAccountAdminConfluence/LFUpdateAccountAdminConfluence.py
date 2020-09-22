from __future__ import print_function
import requests
import json
import botocore
import boto3
import os
import utilitymodules as um

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

def add_account_details(accountlist,accountname,accountid,poc,ppmcid,usageid,toc,envtype,sensitivenonprod,costcenter,expdate,autotag,root_has_mfa):

    account_data = {
        "accountname": accountname,
        "accountid": accountid,
        "poc": poc,
        "usageid": usageid,
        "toc": toc,
        "ppmcid": ppmcid,
        "envtype": envtype,
        "sensitivenonprod": sensitivenonprod,
        "envtype": envtype,
        "costcenter": costcenter,
        "expdate": expdate,
        "autotag": autotag,
        "root_has_mfa": root_has_mfa
    }
    accountlist.append(account_data)
    return accountlist

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

def check_MFA_enabled(credentials):

    root_has_mfa = "NO"
    session = boto3.session.Session()
    iam_client = session.client(
                service_name='iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
    )

    try:
        if iam_client.get_account_summary()['SummaryMap']['AccountMFAEnabled']:
            root_has_mfa = "YES"
    except botocore.exceptions.ClientError as e:
        print(e)
        raise
    finally:
        return root_has_mfa

def extract_account_tag_list(accountlist):

    #Assume role of member account before creating Qualys IAM role within member account
    account_role = 'OrganizationAccountAccessRole'    

    account_tag_list = []
    for account_id in accountlist:

        credentials = assume_role(account_id, account_role)
        root_has_mfa = "NO"
        root_has_mfa = check_MFA_enabled(credentials)
        account_name = ''
        poc = ''
        usageid = ''
        toc = ''
        envtype = ''
        ppmcid = ''
        sensitivenonprod = ''
        costcenter = ''
        autotag = ''
        expirydate = ''
        tagdict = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)
        for tag in tagdict['Tags']:
            if tag['Key'] == 'account-name':
                account_name = tag['Value'].upper()
            elif tag['Key'] == 'poc':
                poc = tag['Value'].upper()
            elif tag['Key'] == 'usage-id':
                usageid = tag['Value'].upper()
            elif tag['Key'] == 'toc':
                toc = tag['Value'].upper()
            elif tag['Key'] == 'env-type':
                envtype = tag['Value'].upper()
            elif tag['Key'] == 'sensitive-nonprod':
                sensitivenonprod = tag['Value'].upper()
            elif tag['Key'] == 'ppmc-id':
                ppmcid = tag['Value']
            elif tag['Key'] == 'cost-center':
                costcenter = tag['Value']
            elif tag['Key'] == 'exp-date':
                expdate = tag['Value']
            elif tag['Key'] == 'auto-tag':
                autotag = tag['Value'].upper()
                
        account_tag_list = add_account_details(account_tag_list,account_name,account_id,poc,ppmcid,usageid,toc,envtype,sensitivenonprod,costcenter,expdate,autotag,root_has_mfa)

    return account_tag_list

def extract_confluence_page_details(service_account):

    #url = "https://confluence.capgroup.com/rest/api/content/282848271"
    url = os.environ['CONFLUENCE_URL']
    headers = {
      "Accept": "application/json",
      'authorization': "Basic " + service_account,
      "Content-Type": "application/json"
    }
    
    response = requests.request(
      "GET",
      url,
      headers=headers
    )

    title = ''
    version = 0
    print(response.status_code)
    if '200' in str(response.status_code):
        response_josn = json.loads(response.text)
        title = response_josn['title']
        version = int(response_josn['version']['number']) + 1

        print("title:", response_josn['title'])
        print("version number:", response_josn['version']['number'])

    return title,version

def format_account_data(account_tag_list):
    data = '<table class="wrapped fixed-table"> \n\
            <colgroup>\n\
            <col style="width: 275.0px;" />\n\
            <col style="width: 125.0px;" /><col style="width: 115.0px;" /><col style="width: 123.0px;" />\n\
            <col style="width: 115.0px;" /><col style="width: 120.0px;" /><col style="width: 102.0px;" />\n\
            <col style="width: 100.0px;" /><col style="width: 130.0px;" /><col style="width: 125.0px;" />\n\
            <col style="width: 125.0px;" /><col style="width: 125.0px;" />\n\
            </colgroup>\n\
            <tbody>\n\
            <tr>\n\
            <th style="text-align: center;" class="confluenceTh"><strong>Account Name</strong></th>\n\
            <th style="text-align: center;" class="confluenceTh">Account ID</th>\n\
            <th style="text-align: center;" class="confluenceTh">POC</th>\n\
            <th style="text-align: center;" class="confluenceTh">Usage ID</th>\n\
            <th style="text-align: center;" class="confluenceTh">TOC</th>\n\
            <th style="text-align: center;" class="confluenceTh">Environment Type</th>\n\
            <th style="text-align: center;" class="confluenceTh">PPMC ID</th>\n\
            <th style="text-align: center;" class="confluenceTh">Cost Center</th>\n\
            <th style="text-align: center;" class="confluenceTh">Expiry Date</th>\n\
            <th style="text-align: center;" class="confluenceTh">Sensitive NonProd</th>\n\
            <th style="text-align: center;" class="confluenceTh">Auto Tag Enabled</th>\n\
            <th style="text-align: center;" class="confluenceTh">Root MFA Enabled</th>\n\
            </tr>'
    
    length = len(account_tag_list)
    accountdata = ''
    for i in range(length):
        account = account_tag_list[i]
        accountdata += '<tr>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['accountname'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['accountid'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['poc'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['usageid'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['toc'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['envtype'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['ppmcid'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['costcenter'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['expdate'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['sensitivenonprod'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['autotag'] + '</td>\n' + \
            '<td style="text-align: center;" colspan="1" class="confluenceTd">' + account['root_has_mfa'] + '</td>\n' + \
            '</tr>'
    
    data = data + accountdata + '</tbody></table>'
    #print(data)
    return data

def update_confleunce_page(data,service_account,version,title):

    is_confluence_page_updated = False
    #url = "https://confluence.capgroup.com/rest/api/content/282848271"
    url = os.environ['CONFLUENCE_URL']
    headers = {
      "Accept": "application/json",
      'authorization': "Basic " + service_account,
      "Content-Type": "application/json"
    }

    payload = json.dumps( {
        "version": {
            "number": version
        },
        "title": title,
        "type": "page",
        "body": {
            "storage": {
                "value": data,
                "representation": "storage"
            }
        }
    })

    response = requests.request(
      "PUT",
      url,
      headers=headers,
      data=payload
    )
    print(response.status_code)
    if '200' in str(response.status_code):
        is_confluence_page_updated = True

    return is_confluence_page_updated

def lambda_handler(event,context):

    is_confluence_page_updated = False

    #Extract list of all AWS accounts
    accountlist = um.list_all_accounts()
    
    #Extract account level tags to be displaced within confluence page 
    account_tag_list = []
    account_tag_list = extract_account_tag_list(accountlist)

    # Format account data to be presented in confluence
    data = format_account_data(account_tag_list)

    #Extract service account credentials to be used to update confleunce page
    secret_name = os.environ['SERVICE_ACCOUNT_CREDENTIALS']
    region_name = os.environ['SECRETS_MANAGER_REGION']
    
    response = get_secret(secret_name,region_name)
    response_dict = json.loads(response)
    service_account = response_dict['IAMServiceAccount']

    #Extract basic details of confleunec page to update its contents
    (title,version) = extract_confluence_page_details(service_account)

    # Refresh confluence page with latest account details
    is_confluence_page_updated = update_confleunce_page(data,service_account,version,title)
    event['is_confluence_page_updated'] = is_confluence_page_updated
    return event