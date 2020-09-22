from __future__ import print_function
import boto3
import botocore
import sys
import argparse
import os
import time
import urllib
import json
from botocore.vendored import requests

def deploy_configrules(deployregion):
    is_configrule_stack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_config_rule(
            OrganizationConfigRuleName='OrganizationConfigRuleRequiredTags',
            OrganizationManagedRuleMetadata={
                'Description': 'Check for untagged resources rule for the entire organization',
                'RuleIdentifier': 'REQUIRED_TAGS',
                'InputParameters': '{ \n  \"tag1Key\" : \"cost-center\", \n  \"tag2Key\" : \"usage-id\",\n  \"tag3Key\" : \"ppmc-id\", \n  \"tag4Key\" : \"toc\", \n  \"tag5Key\" : \"exp-date\", \n  \"tag6Key\" : \"env-type\"\n}',
                'ResourceTypesScope': [
                    "AWS::DynamoDB::Table",
                    "AWS::EC2::Instance",
                    "AWS::EC2::Volume",
                    "AWS::ElasticLoadBalancing::LoadBalancer",
                    "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "AWS::RDS::DBInstance",
                    "AWS::RDS::DBSnapshot",
                    "AWS::Redshift::Cluster",
                    "AWS::Redshift::ClusterSnapshot",
                    "AWS::S3::Bucket",
                    "AWS::Lambda::Function"
                ]
            },
            ExcludedAccounts=[
                "210961756523"
            ]
        )
        print(response)
        is_configrule_stack_created = True
        return is_configrule_stack_created

    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        return is_configrule_stack_created

def lambda_handler(event,context):
    print(event)

    configregions = ["us-west-1","us-east-1","us-east-2","us-west-2"]
    #configregions = ["us-west-1","us-west-2"]

    #iterate through all 4 US regions to deploy template
    for deployregion in configregions:
        print(deployregion)
        is_configrule_stack_created = deploy_configrules(deployregion)
        print("Config rules deployed successfully:"+ str(is_configrule_stack_created))

    event['is_configrule_stack_created'] = is_configrule_stack_created
    print("Config rule deployment for account complete !!")

    return event