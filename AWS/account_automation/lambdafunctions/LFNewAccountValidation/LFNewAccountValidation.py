from __future__ import print_function
import boto3
import botocore
import json

def lambda_handler(event,context):
    print(event)
    detail = event['detail']
    event['is_valid_account'] = False
    if detail['serviceEventDetails']['createAccountStatus']['state'] == 'SUCCEEDED': 
        event['is_valid_account'] = True
        print("Account creation status:" + detail['serviceEventDetails']['createAccountStatus']['state'])
        account_id = detail['serviceEventDetails']['createAccountStatus']['accountId']
        print("Account Id:" + account_id)
        event['account_id'] = account_id
        return event
    else :
        print('Account details not found:', json.dumps(event))
        return event