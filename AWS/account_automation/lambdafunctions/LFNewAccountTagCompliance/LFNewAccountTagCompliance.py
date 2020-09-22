from __future__ import print_function
import boto3
import botocore
import sys
import os

def deploy_tagcomps(stackname, account_id, set_region):
    is_tagcomp_stack_created = False
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
        is_tagcomp_stack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack: {}".format(e))
        raise
    finally:
        return is_tagcomp_stack_created

def lambda_handler(event,context):
    print(event)
    account_id = event['account_id']
    baselinetagcompstack = os.environ['BaselineTagCompStack']
    tagcompregion = os.environ['BaselineTagCompRegion']
    #Deploy in all 4 US regions 
    is_tagcomp_stack_created = deploy_tagcomps(baselinetagcompstack, account_id, tagcompregion)
    print("Tag Compliance alerts deployed successfully:"+ str(is_tagcomp_stack_created))

    event['is_tagcomp_stack_created'] = is_tagcomp_stack_created
    print("Tag Compliance alerts deployment for account " + account_id +  " complete !!")

    return event