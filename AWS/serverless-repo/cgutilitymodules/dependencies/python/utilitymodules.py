from __future__ import print_function
import boto3
import botocore
import time

master_account = '848721808596'
master_role = 'OrganizationsReadAccessRole'
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

def merge_mandatory_tags(old_tags,account_id):

    mandatory_tags_merged = False
    new_tags = {}
    final_tags = {}
    mandatory_tags = {}
    
    try:
        #acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
        tagdict = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)
        for tag in tagdict['Tags']:
            if tag['Key'] == 'usage-id':
                mandatory_tags['usage-id'] = tag['Value'].upper()
            elif tag['Key'] == 'toc':
                mandatory_tags['toc'] = tag['Value'].upper()
            elif tag['Key'] == 'env-type':
                mandatory_tags['env-type'] = tag['Value'].upper()
            elif tag['Key'] == 'ppmc-id':
                mandatory_tags['ppmc-id'] = tag['Value']
            elif tag['Key'] == 'cost-center':
                mandatory_tags['cost-center'] = tag['Value']
            elif tag['Key'] == 'exp-date':
                mandatory_tags['exp-date'] = tag['Value']
            elif tag['Key'] == 'sd-period':
                mandatory_tags['sd-period'] = tag['Value'].upper()
        #mandatory_tags = {i['Key']: i['Value'] for i in acctags}
        new_tags = {**mandatory_tags, **old_tags}
        for Key, Value in new_tags.items():
            if 'aws:' not in str(Key):
                final_tags.update({str(Key): str(Value)})
        mandatory_tags_merged = True
    except Exception as e:
        print(e)
    finally:
        return mandatory_tags_merged,final_tags

def merge_mandatory_tags_from_master(old_tags,account_id):

    credentials = assume_role(master_account, master_role)
    session = boto3.session.Session()
    client = session.client(
                service_name='organizations',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
    mandatory_tags_merged = False
    new_tags = {}
    final_tags = {}
    mandatory_tags = {}

    try:
        tagdict = client.list_tags_for_resource(ResourceId=account_id)
        for tag in tagdict['Tags']:
            if tag['Key'] == 'usage-id':
                mandatory_tags['usage-id'] = tag['Value'].upper()
            elif tag['Key'] == 'toc':
                mandatory_tags['toc'] = tag['Value'].upper()
            elif tag['Key'] == 'env-type':
                mandatory_tags['env-type'] = tag['Value'].upper()
            elif tag['Key'] == 'ppmc-id':
                mandatory_tags['ppmc-id'] = tag['Value']
            elif tag['Key'] == 'cost-center':
                mandatory_tags['cost-center'] = tag['Value']
            elif tag['Key'] == 'exp-date':
                mandatory_tags['exp-date'] = tag['Value']
            elif tag['Key'] == 'sd-period':
                mandatory_tags['sd-period'] = tag['Value'].upper()

        new_tags = {**mandatory_tags, **old_tags}
        for Key, Value in new_tags.items():
            if 'aws:' not in str(Key):
                final_tags.update({str(Key): str(Value)})
        mandatory_tags_merged = True
    except Exception as e:
        print(e)
    finally:
        return mandatory_tags_merged,final_tags

def list_all_accounts():

    org_root_id = 'r-uj02'
    client = boto3.client('organizations')
    paginator = client.get_paginator('list_children')
   
    out_list = []
    sub_out_list = []
    account_list = []
    
    response_iterator_acc = paginator.paginate(ParentId=org_root_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
    # print ('###### List of accounts in root :')
    for page in response_iterator_acc:
        for accounts in page['Children']:
            # print (accounts['Id'])
            account_list.append(accounts['Id'])

    response_iterator_org_ou = paginator.paginate(ParentId=org_root_id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
    # print ('\n###### List of OU in root :')
    for page in response_iterator_org_ou:
        for out in page['Children']:
            out_list.append(out['Id']) 
            # print (out['Id'])
    
    for id in out_list: 
        # print (id)
        response_iterator_acc_level_one = paginator.paginate(ParentId=id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
        # print ('\nList of accounts in level one OU Id: ', id)
        for page in response_iterator_acc_level_one:
            for accounts in page['Children']:
                # print (accounts['Id'])
                account_list.append(accounts['Id'])
    
        
        response_iterator_org_ou_level_one = paginator.paginate(ParentId=id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
        for page in response_iterator_org_ou_level_one:
            if not page['Children']:
                print (id, 'Do not have sub OU ')
            else:
                # print (id, 'Have sub OU')           
                for sub_id in page['Children']:
                    sub_out_list.append(sub_id['Id']) 
                    # print (sub_id['Id'])
                
                for sub_id in sub_out_list:
                    response_iterator_acc_level_two = paginator.paginate(ParentId=sub_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
                    # print ('\nList of accounts in level two OU Id: ', sub_id)
                    for page in response_iterator_acc_level_two:
                        for accounts in page['Children']:
                            # print (accounts['Id'])
                            account_list.append(accounts['Id'])

    return account_list

def list_accounts_by_ou(ou_id):

    org_root_id = root_id
    client = boto3.client('organizations')
    paginator = client.get_paginator('list_children')
   
    out_list = []
    sub_out_list = []
    account_list = []
    
    response_iterator_acc = paginator.paginate(ParentId=org_root_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
    # print ('###### List of accounts in root :')
    for page in response_iterator_acc:
        for accounts in page['Children']:
            # print (accounts['Id'])
            account_list.append(accounts['Id'])

    response_iterator_org_ou = paginator.paginate(ParentId=org_root_id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
    # print ('\n###### List of OU in root :')
    for page in response_iterator_org_ou:
        for out in page['Children']:
            out_list.append(out['Id']) 
            # print (out['Id'])
    
    for id in out_list: 
        # print (id)
        response_iterator_acc_level_one = paginator.paginate(ParentId=id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
        # print ('\nList of accounts in level one OU Id: ', id)
        for page in response_iterator_acc_level_one:
            for accounts in page['Children']:
                # print (accounts['Id'])
                account_list.append(accounts['Id'])
    
        
        response_iterator_org_ou_level_one = paginator.paginate(ParentId=id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
        for page in response_iterator_org_ou_level_one:
            if not page['Children']:
                print (id, 'Do not have sub OU ')
            else:
                # print (id, 'Have sub OU')           
                for sub_id in page['Children']:
                    sub_out_list.append(sub_id['Id']) 
                    # print (sub_id['Id'])
                
                for sub_id in sub_out_list:
                    response_iterator_acc_level_two = paginator.paginate(ParentId=sub_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
                    # print ('\nList of accounts in level two OU Id: ', sub_id)
                    for page in response_iterator_acc_level_two:
                        for accounts in page['Children']:
                            # print (accounts['Id'])
                            account_list.append(accounts['Id'])

    return account_list

def list_accounts_by_ou_from_master(ou_id):

    credentials = assume_role(master_account, master_role)
    org_root_id = ou_id
    session = boto3.session.Session()
    client = session.client(
                service_name='organizations',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
    paginator = client.get_paginator('list_children')
   
    out_list = []
    sub_out_list = []
    account_list = []
    
    response_iterator_acc = paginator.paginate(ParentId=org_root_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
    # print ('###### List of accounts in root :')
    for page in response_iterator_acc:
        for accounts in page['Children']:
            # print (accounts['Id'])
            account_list.append(accounts['Id'])

    response_iterator_org_ou = paginator.paginate(ParentId=org_root_id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
    # print ('\n###### List of OU in root :')
    for page in response_iterator_org_ou:
        for out in page['Children']:
            out_list.append(out['Id']) 
            # print (out['Id'])
    
    for id in out_list: 
        # print (id)
        response_iterator_acc_level_one = paginator.paginate(ParentId=id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
        # print ('\nList of accounts in level one OU Id: ', id)
        for page in response_iterator_acc_level_one:
            for accounts in page['Children']:
                # print (accounts['Id'])
                account_list.append(accounts['Id'])
    
        
        response_iterator_org_ou_level_one = paginator.paginate(ParentId=id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
        for page in response_iterator_org_ou_level_one:
            if not page['Children']:
                print (id, 'Do not have sub OU ')
            else:
                # print (id, 'Have sub OU')           
                for sub_id in page['Children']:
                    sub_out_list.append(sub_id['Id']) 
                    # print (sub_id['Id'])
                
                for sub_id in sub_out_list:
                    response_iterator_acc_level_two = paginator.paginate(ParentId=sub_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
                    # print ('\nList of accounts in level two OU Id: ', sub_id)
                    for page in response_iterator_acc_level_two:
                        for accounts in page['Children']:
                            # print (accounts['Id'])
                            account_list.append(accounts['Id'])

    return account_list

def list_all_accounts_from_master():

    credentials = assume_role(master_account, master_role)
    org_root_id = 'r-uj02'
    session = boto3.session.Session()
    client = session.client(
                service_name='organizations',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
    paginator = client.get_paginator('list_children')
   
    out_list = []
    sub_out_list = []
    account_list = []
    
    response_iterator_acc = paginator.paginate(ParentId=org_root_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
    # print ('###### List of accounts in root :')
    for page in response_iterator_acc:
        for accounts in page['Children']:
            # print (accounts['Id'])
            account_list.append(accounts['Id'])

    response_iterator_org_ou = paginator.paginate(ParentId=org_root_id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
    # print ('\n###### List of OU in root :')
    for page in response_iterator_org_ou:
        for out in page['Children']:
            out_list.append(out['Id']) 
            # print (out['Id'])
    
    for id in out_list: 
        # print (id)
        response_iterator_acc_level_one = paginator.paginate(ParentId=id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
        # print ('\nList of accounts in level one OU Id: ', id)
        for page in response_iterator_acc_level_one:
            for accounts in page['Children']:
                # print (accounts['Id'])
                account_list.append(accounts['Id'])
    
        
        response_iterator_org_ou_level_one = paginator.paginate(ParentId=id,ChildType='ORGANIZATIONAL_UNIT',PaginationConfig={'MaxItems': 123})
        for page in response_iterator_org_ou_level_one:
            if not page['Children']:
                print (id, 'Do not have sub OU ')
            else:
                # print (id, 'Have sub OU')           
                for sub_id in page['Children']:
                    sub_out_list.append(sub_id['Id']) 
                    # print (sub_id['Id'])
                
                for sub_id in sub_out_list:
                    response_iterator_acc_level_two = paginator.paginate(ParentId=sub_id,ChildType='ACCOUNT',PaginationConfig={'MaxItems': 123})
                    # print ('\nList of accounts in level two OU Id: ', sub_id)
                    for page in response_iterator_acc_level_two:
                        for accounts in page['Children']:
                            # print (accounts['Id'])
                            account_list.append(accounts['Id'])

    return account_list