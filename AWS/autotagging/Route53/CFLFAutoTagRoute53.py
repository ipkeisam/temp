from __future__ import print_function
import json
import os
import boto3
import logging
import time
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)
#hostedzone   
def set_resource_route53_hosted_tags(credentials, id, account_id):
  old_tags = []
  new_tags = []
  id1=id.split("/")[2]
  session = boto3.session.Session()
  route53_client=boto3.client(
                      service_name='route53',
                      aws_access_key_id=credentials['AccessKeyId'],
                      aws_secret_access_key=credentials['SecretAccessKey'],
                      aws_session_token=credentials['SessionToken']
                  )
  acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
  #mandatory_tags = {i['Key']: i['Value'] for i in acctags}
  try:
    old_tags = route53_client.list_tags_for_resource(ResourceType='hostedzone',ResourceId=id1)['ResourceTagSet']['Tags']
  except Exception as e:
    print(e)
  new_tags = acctags + old_tags
  print('Tagging resource ' + id1)
  try:
    response=route53_client.change_tags_for_resource(ResourceType='hostedzone',ResourceId=id1,AddTags=new_tags)
    print(response)
    return True
  except Exception as e:
    print(e)
    return False
#healthcheck
def set_resource_route53_health_tags(credentials, id, account_id):
  old_tags = []
  new_tags = []
  id1=id.split("/")[2]
  session = boto3.session.Session()
  route53_client=boto3.client(
                      service_name='route53',
                      aws_access_key_id=credentials['AccessKeyId'],
                      aws_secret_access_key=credentials['SecretAccessKey'],
                      aws_session_token=credentials['SessionToken']
                  )
  acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
  #mandatory_tags = {i['Key']: i['Value'] for i in acctags}
  
  try:
    old_tags = route53_client.list_tags_for_resource(ResourceType='healthcheck',ResourceId=id1)['ResourceTagSet']['Tags']
  except Exception as e:
    print(e)
  new_tags = acctags + old_tags
  print('Tagging resource ' + id1)
  try:
    response=route53_client.change_tags_for_resource(ResourceType='healthcheck',ResourceId=id1,AddTags=new_tags)
    print(response)
    return True
  except Exception as e:
    print(e)
    return False
#route53resolver
def set_resource_route53_resolver_tags(credentials, resolver_arn, account_id):
  old_tags = []
  new_tags =[]
  session = boto3.session.Session()
  route53_client=boto3.client(
                      service_name='route53resolver',
                      aws_access_key_id=credentials['AccessKeyId'],
                      aws_secret_access_key=credentials['SecretAccessKey'],
                      aws_session_token=credentials['SessionToken']
                  )
  acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
  #mandatory_tags = {i['Key']: i['Value'] for i in acctags}
  try:
    old_tags = route53_client.list_tags_for_resource(ResourceArn = resolver_arn)['Tags']
  except Exception as e:
    print(e)
  new_tags = acctags + old_tags
  print('Tagging resource ' + resolver_arn)
  try:
    response=route53_client.tag_resource(ResourceArn= resolver_arn,Tags=new_tags)
    print(response)
    return True
  except Exception as e:
    print(e)
    return False
#route53domain
def set_resource_route53_domain_tags(credentials, domain, account_id):
  old_tags = []
  new_tags = []
  session = boto3.session.Session()
  route53_client=boto3.client(
                      service_name='route53domains',
                      aws_access_key_id=credentials['AccessKeyId'],
                      aws_secret_access_key=credentials['SecretAccessKey'],
                      aws_session_token=credentials['SessionToken']
                  )
  acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
  #mandatory_tags = {i['Key']: i['Value'] for i in acctags} 
  try:
    old_tags = route53_client.list_tags_for_domain(DomainName= domain)['TagList']
  except Exception as e:
    print(e)  
  new_tags = mandatory_tags + old_tags
  print('Tagging resource ' + domain)
  try:
    response=route53_client.update_tags_for_domain(DomainName=domain,TagsToUpdate=new_tags)
    print(response)
    return True
  except Exception as e:
    print(e)
    return False

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


def lambda_handler(event, context):
  try:
    region=event['detail']['awsRegion']
    detail=event['detail']
    account_id = detail['userIdentity']['accountId']
    eventname=event['detail']['eventName']   
    logger.info('region: ' + str(region))
    logger.info('eventName: ' + str(eventname))
    logger.info('detail: ' + str(detail))
    id=[]
    ids=[]
    arn=[]
    domains=[]

    if not detail['requestParameters']:
      logger.warning('No requestParameters found')
      if detail['errorCode']:
        logger.error('errorCode: ' + detail['errorCode'])
      if detail['errorMessage']:
        logger.error('errorMessage: ' + detail['errorMessage'])
      return False
    
    if account_id == '848721808596':
      return False

    if eventname == 'CreateHealthCheck':
        id.append(detail['responseElements']['healthCheck']['id'])
        logger.info(id)
    elif eventname == 'CreateHostedZone':
        ids.append(detail['responseElements']['hostedZone']['id'])
        logger.info(ids)
    elif eventname == 'CreateQueryLoggingConfig':
        ids.append(detail['responseElements']['queryLoggingConfig']['id'])
        logger.info(ids)
    elif eventname == 'CreateReusableDelegationSet':
        ids.append(detail['responseElements']['delegationSet']['id'])
        logger.info(ids)
    elif eventname == 'CreateTrafficPolicy':
        ids.append(detail['responseElements']['trafficPolicy']['id'])
        logger.info(ids)
    elif eventname == 'CreateTrafficPolicyInstance':
        ids.append(detail['responseElements']['trafficPolicyInstance']['id'])
        logger.info(ids)
    elif eventname == 'CreateTrafficPolicyVersion':
        ids.append(detail['responseElements']['trafficPolicy']['id'])
        logger.info(ids)
    elif eventname == 'CreateVPCAssociationAuthorization':
        ids.append(detail['responseElements']['vpc']['vpcId'])
        logger.info(ids)
    elif eventname == 'CreateResolverEndpoint':
        arn.append(detail['responseElements']['resolverEndpoint']['arn'])
        logger.info(id2)
    elif eventname == 'CreateResolverRule':
        arn.append(detail['responseElements']['resolverRule']['arn'])
        logger.info(id2)
    else:
      logger.warning('Not supported action')

    #Assume role of member account before tagging Route53 resources
    account_role = 'OrganizationAccountAccessRole'
    credentials = assume_role(account_id, account_role)

    if id:
        for resourceids in id:
            response = set_resource_route53_health_tags(credentials, resourceids, account_id)
        return response
    if ids:
        for resourceids in ids:
            response = set_resource_route53_hosted_tags(credentials, resourceids, account_id)
        return response
    #This is for domain availability    
    elif id1:
        for resourceids in domains:
            response = set_resource_route53_domain_tags(credentials, resourceids, account_id)
        return response
    elif id2:
        for resourceids in arn:
            response = set_resource_route53_resolver_tags(credentials, resourceids, account_id)
        return response
    else:   
        return False
  except Exception as e:
    logger.error('Error message: ' + str(e))
    return False