from __future__ import print_function
import boto3
import botocore
import json
import time

def deploy_tagconfigrule(deployregion):
    is_tagconfigrule_created = False
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
        is_tagconfigrule_created = True

    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_tagconfigrule_created

def deploy_s3conformancepack(deployregion):

    conformancepackname = "S3ConformancePack"
    deliverybucket = "awsconfigconforms-848721808596"
    tempaltes3uri = "s3://organization-repo/conformancepacks/CFS3ConformancePackTemplate.yml"
    is_s3conformancepack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_conformance_pack(
            OrganizationConformancePackName=conformancepackname,
            TemplateS3Uri=tempaltes3uri,
            DeliveryS3Bucket=deliverybucket
        )
        print(response)
        is_s3conformancepack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_s3conformancepack_created

def deploy_mlconformancepack(deployregion):

    conformancepackname = "MLConformancePack"
    deliverybucket = "awsconfigconforms-848721808596"
    tempaltes3uri = "s3://organization-repo/conformancepacks/CFMLConformancePackTemplate.yml"
    is_mlconformancepack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_conformance_pack(
            OrganizationConformancePackName=conformancepackname,
            TemplateS3Uri=tempaltes3uri,
            DeliveryS3Bucket=deliverybucket
        )
        print(response)
        is_mlconformancepack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_mlconformancepack_created

def deploy_encryptionconformancepack(deployregion):

    conformancepackname = "EncryptionConformancePack"
    deliverybucket = "awsconfigconforms-848721808596"
    tempaltes3uri = "s3://organization-repo/conformancepacks/CFEncryptionConformancePackTemplate.yml"
    is_encryptionconformancepack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_conformance_pack(
            OrganizationConformancePackName=conformancepackname,
            TemplateS3Uri=tempaltes3uri,
            DeliveryS3Bucket=deliverybucket
        )
        print(response)
        is_encryptionconformancepack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_encryptionconformancepack_created

def deploy_publicconformancepack(deployregion):

    conformancepackname = "PubliclyAccessibleConformancePack"
    deliverybucket = "awsconfigconforms-848721808596"
    tempaltes3uri = "s3://organization-repo/conformancepacks/CFPubliclyAccessibleConformancePackTemplate.yml"
    is_publicconformancepack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_conformance_pack(
            OrganizationConformancePackName=conformancepackname,
            TemplateS3Uri=tempaltes3uri,
            DeliveryS3Bucket=deliverybucket
        )
        print(response)
        is_publicconformancepack_created = True
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        raise
    finally:
        return is_publicconformancepack_created

def lambda_handler(event,context):
    print(event)
    are_tagconfigrules_created = {}
    are_s3conformancepacks_created = {}
    are_mlconformancepacks_created = {}
    are_encrptionconformancepacks_created = {}
    are_paconformancepacks_created = {}
    configregions = ["us-west-1","us-east-1","us-east-2","us-west-2"]
    #configregions = ["us-west-1","us-west-2"]
    length = len(configregions)

    #iterate through all 4 US regions to deploy template
    for i in range(length):
        
        deployregion = configregions[i]
        print(deployregion)
        is_tagconfigrule_created = deploy_tagconfigrule(deployregion)
        are_tagconfigrules_created.update({deployregion:is_tagconfigrule_created})
        is_s3conformancepack_created = deploy_s3conformancepack(deployregion)
        are_s3conformancepacks_created.update({deployregion:is_s3conformancepack_created})
        is_mlconformancepack_created = deploy_mlconformancepack(deployregion)
        are_mlconformancepacks_created.update({deployregion:is_mlconformancepack_created})
        is_encryptionconformancepack_created = deploy_encryptionconformancepack(deployregion)
        are_encrptionconformancepacks_created.update({deployregion:is_encryptionconformancepack_created})
        is_paconformancepack_created = deploy_publicconformancepack(deployregion)
        are_paconformancepacks_created.update({deployregion:is_paconformancepack_created})
        if i < length-1:
            time.sleep(60)
            
    event['are_tagconfigrules_created'] = are_tagconfigrules_created
    event['are_s3conformancepacks_created'] = are_s3conformancepacks_created
    event['are_mlconformancepacks_created'] = are_mlconformancepacks_created
    event['are_encrptionconformancepacks_created'] = are_encrptionconformancepacks_created
    event['are_paconformancepacks_created'] = are_paconformancepacks_created
    print("Config rule deployment for account complete !!")

    return event