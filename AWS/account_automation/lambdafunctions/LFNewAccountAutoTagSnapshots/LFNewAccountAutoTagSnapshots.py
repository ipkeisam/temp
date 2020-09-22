from __future__ import print_function
import boto3
import botocore
import os

def deploy_stackset(stackname, account_id, set_region):
    is_autotag_snapshot_created = False
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
        is_autotag_snapshot_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack: {}".format(e))
        raise
    finally:
        return is_autotag_snapshot_created

def lambda_handler(event,context):
    print(event)
    account_id = event['account_id']
    baselinestack = os.environ['BaselineStack']
    baselineregion = os.environ['BaselineRegion']
    #Deploy in all 4 US regions 
    is_autotag_snapshot_created = deploy_stackset(baselinestack, account_id, baselineregion)
    print("AutoTagging Snapshots module deployed successfully:"+ str(is_autotag_snapshot_created))
    event['is_autotag_snapshot_created'] = is_autotag_snapshot_created
    return event