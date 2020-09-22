import os
import boto3
import botocore

def create_case(account_id):
    """
    Creates a support case requesting to enable Enterprise Support.

    :param account_ids: list of str
    :return: string
    """
    display_id = ''
    support_client = boto3.client('support', region_name='us-east-1')

    company_name = os.environ['CompanyName']
    case_subject = f'Enable {company_name} Enterprise Support on new accounts'
    case_severity_code = 'low'
    case_category_code = 'other-account-issues'
    case_service_code = 'customer-account'
    accounts = account_id
    case_communication_body = f'Hi AWS! Please enable Enterprise Support on new account ID {accounts} with the same ' \
        f'support plan as this Payer account. This case was created automatically - please resolve when done.'
    case_cc_emails = os.environ['ccEmailAddresses']
    case_issue_type = 'customer-service'

    try:
        response = support_client.create_case(
            subject=case_subject,
            severityCode=case_severity_code,
            categoryCode=case_category_code,
            serviceCode=case_service_code,
            communicationBody=case_communication_body,
            ccEmailAddresses=[case_cc_emails],
            language='en',
            issueType=case_issue_type
        )
        # Print Case ID to return.
        case_id = response['caseId']
        case = support_client.describe_cases(
            caseIdList=[case_id])
        display_id = case['cases'][0]['displayId']

        print(f'Case {display_id} opened for accounts {accounts}.')
    except botocore.exceptions.ClientError as e:
        print("Error creating a new case. Error : {}".format(e))
        raise
    finally:
        return display_id    



def lambda_handler(event,context):
    
    is_entsupport_ticket_opened = False
    account_id = event['account_id']
    #Import wrapped key into the original key created for the resource
    #response = import_key_material(credentials,keyid,importtoken,wrappedkey,deployregion)
    response = create_case(account_id)
    print(response)
    if response:
        is_entsupport_ticket_opened = True
    event['is_entsupport_ticket_opened'] = is_entsupport_ticket_opened
    return event