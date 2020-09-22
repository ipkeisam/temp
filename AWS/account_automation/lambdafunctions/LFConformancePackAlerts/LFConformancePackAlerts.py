from __future__ import print_function
import boto3
import botocore
import sys
import os

def deploy_conformancepack_alerts(stackname, account_id, set_region):
    is_conformancepack_stack_executed = False
    client = boto3.client('cloudformation', region_name=set_region)
    print("Updating stackset " + stackname + " in " + account_id)
    try:
        create_stack_response = client.create_stack_instances(
            StackSetName=stackname,
            Accounts=[
                account_id,
            ],
            Regions=[
                'us-west-1',
                'us-west-2',
                'us-east-1',
                'us-east-2',
            ]
        )
        is_conformancepack_stack_executed = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack: {}".format(e))
        raise
    finally:
        return is_conformancepack_stack_executed

def lambda_handler(event,context):
    print(event)
    account_id = event['account_id']
    baselinestack = os.environ['BaselineConformanceStack']
    region = os.environ['BaselineConformanceRegion']
    #Deploy in all 4 US regions 
    is_conformancepack_stack_executed = deploy_conformancepack_alerts(baselinestack, account_id, region)
    print("Conformance Pack alerts deployed successfully:"+ str(is_conformancepack_stack_executed))

    event['is_conformancepack_stack_executed'] = is_conformancepack_stack_executed
    return event