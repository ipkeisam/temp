import boto3, botocore, logging
import time
import json

log = logging.getLogger()
log.setLevel(logging.INFO)

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

def lambda_handler(event,context):

    event['is_account_moved_to_ou'] = False
    account_id = event['account_id']
    organization_unit_name = event['organization_unit_name']
    environmenttype = event['environment_type']

    org_client = boto3.client('organizations')
    try:
        list_roots_response = org_client.list_roots()
        log.info(list_roots_response)
        root_id = list_roots_response['Roots'][0]['Id']
    except:
        root_id = "Error"

    if root_id  != "Error":
       
        try:
            org_client = boto3.client('organizations')
            organization_unit_id = get_ou_name_id(root_id,organization_unit_name,environmenttype)
            move_response = org_client.move_account(AccountId=account_id,SourceParentId=root_id,DestinationParentId=organization_unit_id)
            event['is_account_moved_to_ou'] = True
        except Exception as ex:
            log.info(ex)
            raise
        finally:
            return event
    else:
        log.info("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
        return event