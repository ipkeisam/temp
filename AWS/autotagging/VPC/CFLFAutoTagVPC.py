from __future__ import print_function
import json
import os
import boto3
import logging
import time
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def set_resource_tags(credentials, resource_id, account_id):
    old_tags = {}
    new_tags = {}
    session = boto3.session.Session()
    ec2_client=boto3.client(
                        service_name='ec2',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                    )
    acctags = boto3.client('organizations').list_tags_for_resource(ResourceId=account_id)['Tags']
    mandatory_tags = {i['Key']: i['Value'] for i in acctags}
            
    try:
        old = ec2_client.describe_tags(
            Filters=[
                {
                    'Name': 'resource-id',
                    'Values': [
                        resource_id[0],
                    ],
                },
            ],
        )
        old_tags = {i['Key']: i['Value'] for i in old['Tags']}
    except Exception as e:
        print(e)
    new_tags = {**mandatory_tags, **old_tags}
    print('Tagging resource ' + resource_id)

    try:
        resourceid=[]
        resourceid.append(resource_id)
        response = ec2_client.create_tags(
            Resources=resourceid,
            Tags=[
                {'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()
            ]
        )
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
        ids=[]

        if not detail['requestParameters']:
            logger.warning('No requestParameters found')
            if detail['errorCode']:
                logger.error('errorCode: ' + detail['errorCode'])
            if detail['errorMessage']:
                logger.error('errorMessage: ' + detail['errorMessage'])
            return False
        
        if account_id == '848721808596':
            return False
        if eventname == 'CreateCustomerGateway':
            ids.append(detail['responseElements']['customerGateway']['customerGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateDefaultSubnet':
            ids.append(detail['responseElements']['subnet']['subnetId'])
            logger.info(ids)
        elif eventname == 'CreateDefaultVpc':
            ids.append(detail['responseElements']['vpc']['vpcId'])
            logger.info(ids)
        elif eventname == 'CreateDhcpOptions':
            ids.append(detail['responseElements']['dhcpOptions']['dhcpOptionsId'])
            logger.info(ids)
        elif eventname == 'CreateEgressOnlyInternetGateway':
            ids.append(detail['responseElements']['egressOnlyInternetGateway']['egressOnlyInternetGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateFlowLogs':
            ids.append(detail['responseElements']['flowLogIdSet'])
            logger.info(ids)
        elif eventname == 'CreateInternetGateway':
            ids.append(detail['responseElements']['internetGateway']['internetGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateNatGateway':
            ids.append(detail['responseElements']['natGateway']['natGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateNetworkAcl':
            ids.append(detail['responseElements']['networkAcl']['networkAclId'])
            logger.info(ids)
        elif eventname == 'CreateNetworkInterface':
            ids.append(detail['responseElements']['networkInterface']['networkInterfaceId'])
            logger.info(ids)
        elif eventname == 'CreateNetworkInterfacePermission':
            ids.append(detail['responseElements']['interfacePermission']['networkInterfacePermissionId'])
            logger.info(ids)
        elif eventname == 'CreateRouteTable':
            ids.append(detail['responseElements']['routeTable']['routeTableId'])
            logger.info(ids)
        elif eventname == 'CreateSecurityGroup': 
            ids.append(detail['responseElements']['groupId'])
            logger.info(ids)
        elif eventname == 'CreateSubnet':
            ids.append(detail['responseElements']['subnet']['subnetId'])
            logger.info(ids)
        elif eventname == 'CreateVpc':
            ids.append(detail['responseElements']['vpc']['vpcId'])
            logger.info(ids)
        elif eventname == 'CreateVpcEndpoint':
            ids.append(detail['responseElements']['vpcEndpoint']['vpcEndpointId'])
            logger.info(ids)
        elif eventname == 'CreateVpcEndpointConnectionNotification':
            ids.append(detail['responseElements']['connectionNotification']['connectionNotificationId'])
            logger.info(ids)
        elif eventname == 'CreateVpcEndpointServiceConfiguration':
            ids.append(detail['responseElements']['serviceConfiguration']['serviceId'])
            logger.info(ids)
        elif eventname == 'CreateVpcPeeringConnection':
            ids.append(detail['responseElements']['vpcPeeringConnection']['vpcPeeringConnectionId'])
            logger.info(ids)
        elif eventname == 'CreateVpnConnection':
            ids.append(detail['responseElements']['vpnConnection']['vpnConnectionId'])
            logger.info(ids)
        elif eventname == 'CreateVpnGateway':
            ids.append(detail['responseElements']['vpnGateway']['vpnGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGateway':
            ids.append(detail['responseElements']['CreateTransitGatewayResponse']['transitGateway']['transitGatewayId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGatewayMulticastDomain':
            ids.append(detail['responseElements']['CreateTransitGatewayMulticastDomainResponse']['transitGatewayMulticastDomain']['transitGatewayMulticastDomainId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGatewayPeeringAttachment':
            ids.append(detail['responseElements']['CreateTransitGatewayPeeringAttachmentResponse']['TransitGatewayPeeringAttachment']['transitGatewayAttachmentId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGatewayRoute':
            ids.append(detail['responseElements']['CreateTransitGatewayRouteResponse']['route']['transitGatewayAttachments']['transitGatewayAttachmentId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGatewayRouteTable':
            ids.append(detail['responseElements']['CreateTransitGatewayRouteTableResponse']['transitGatewayRouteTable']['transitGatewayRouteTableId'])
            logger.info(ids)
        elif eventname == 'CreateTransitGatewayVpcAttachment':
            ids.append(detail['responseElements']['CreateTransitGatewayVpcAttachmentResponse']['transitGatewayVpcAttachment']['transitGatewayAttachmentId'])
            logger.info(ids)
        elif eventname == 'CreateTrafficMirrorFilter':
            ids.append(detail['responseElements']['trafficMirrorFilter']['trafficMirrorFilterId'])
            logger.info(ids)
        elif eventname == 'CreateTrafficMirrorFilterRule':
            ids.append(detail['responseElements']['trafficMirrorFilterRule']['trafficMirrorFilterRuleId'])
            logger.info(ids)
        elif eventname == 'CreateTrafficMirrorSession':
            ids.append(detail['responseElements']['trafficMirrorSession']['trafficMirrorSessionId'])
            logger.info(ids)
        elif eventname == 'CreateTrafficMirrorTarget':
            ids.append(detail['responseElements']['trafficMirrorTarget']['trafficMirrorTargetId'])
            logger.info(ids)
        else:
            logger.warning('Not supported action')

        #Assume role of member account before tagging VPC resource
        account_role = 'OrganizationAccountAccessRole'
        credentials = assume_role(account_id, account_role)

        if ids:
            for resourceids in ids:
                set_resource_tags(credentials,resourceids,account_id)
            return True
        else:
            return False
    except Exception as e:
        logger.error('Error message: ' + str(e))
        return False
