#!/usr/bin/env python
import boto3
import sys
import time
import argparse
import re

from collections import OrderedDict
from botocore.exceptions import ClientError

def assume_role(aws_account_number, role_name):
    sts_client = boto3.client('sts')
    print('Debug: Below is role')
    print('arn:aws:iam::{}:role/{}'.format(aws_account_number, role_name))
    response = sts_client.assume_role(
        RoleArn='arn:aws:iam::{}:role/{}'.format(aws_account_number, role_name),
        RoleSessionName='MasterEnableGuardDuty'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for {}.".format(aws_account_number))
    return session


def get_master_members(msession, aws_region, detector_id):
    """
    Returns a list of current members of the GuardDuty master account
    :param aws_region: AWS Region of the GuardDuty master account
    :param detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """

    member_dict = dict()

    gd_client = msession.client('guardduty', region_name=aws_region)

    # Need to paginate and iterate over results
    paginator = gd_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }

    page_iterator = paginator.paginate(**operation_parameters)

    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update({member['AccountId']: member['RelationshipStatus']})

    return member_dict


def list_detectors(client, aws_region):
    """
    Lists the detectors in a given Account/Region
    Used to detect if a detector exists already
    :param client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """

    detector_dict = client.list_detectors()

    if detector_dict['DetectorIds']:
        for detector in detector_dict['DetectorIds']:
            detector_dict.update({aws_region: detector})

    else:
        detector_dict.update({aws_region: ''})

    return detector_dict


def lambda_handler(event, context):
#if __name__ == '__main__':
    is_guardduty_enabled = False
    master_account = "111417557820" #secfoundation
    assumed_role = "OrganizationAccountAccessRole"
    #Retrieve account id and email from State Machine event variable
    account_id = event['account_id']
    account_email = event['account_email']
    aws_account_dict = OrderedDict()
    aws_account_dict[account_id] = account_email
    # aws_account_dict["011728106311"]="aws-cc2-ndev01@capgroup.com"
    
    # Validate master accountId
    if not re.match(r'[0-9]{12}',master_account):
        raise ValueError("Master AccountId is not valid")

    for key, value in aws_account_dict.items():
        if not re.match(r'[0-9]{12}', str(key)):
            print("Invalid member account number {}, skipping".format(key))
            continue

    # Check length of accounts to be processed
    if len(aws_account_dict.keys()) > 1000:
        raise Exception("Only 1000 accounts can be linked to a single master account")

    # master account session
    msession = assume_role(master_account, assumed_role)
    
    #guardduty_regions = msession.get_available_regions('guardduty')
    #print("Enabling members in all available GuardDuty regions {}".format(guardduty_regions))
    #sys.exit(1)
    guardduty_regions = ['us-west-1','us-west-2','us-east-1','us-east-2']
    # Setting the invitationmessage
    gd_invite_message = 'Account {account} invites you to join GuardDuty.'.format(account=master_account)

    master_detector_id_dict = dict()
    failed_master_regions = []
    # Processing Master account
    for aws_region in guardduty_regions:
        try: 
            gd_client = msession.client('guardduty', region_name=aws_region)

            detector_dict = list_detectors(gd_client, aws_region)

            if detector_dict[aws_region]:
                # a detector exists
                print('Master Acc: Found existing detector {detector} in {region} for {account}'.format(
                    detector=detector_dict[aws_region],
                    region=aws_region,
                    account=master_account
                ))

                master_detector_id_dict.update({aws_region: detector_dict[aws_region]})

            else:

                # create a detector
                detector_str = gd_client.create_detector(Enable=True)['DetectorId']
                print('Created detector {detector} in {region} for {account}'.format(
                    detector=detector_str,
                    region=aws_region,
                    account=master_account
                ))

                master_detector_id_dict.update({aws_region: detector_str})
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print("Failed to list detectors in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue").format(aws_region,aws_region)
                failed_master_regions.append(aws_region)

    for failed_region in failed_master_regions:
        guardduty_regions.remove(failed_region)            
           
    # Processing accounts to be linked
    failed_accounts = []
    for account in aws_account_dict.keys():
        try:
            session = assume_role(account, assumed_role)

            for aws_region in guardduty_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))
                gd_client = session.client('guardduty', region_name=aws_region)

                # get detectors for this region
                detector_dict = list_detectors(gd_client, aws_region)
                detector_id = detector_dict[aws_region]

                # If detector does not exist, create it
                if detector_id:
                    # a detector exists
                    print('Child ACC: Found existing detector {detector} in {region} for {account}'.format(
                        detector=detector_id,
                        region=aws_region,
                        account=account
                    ))

                else:
                    # create a detector
                    detector_str = gd_client.create_detector(Enable=True)['DetectorId']
                    print('Created detector {detector} in {region} for {account}'.format(
                        detector=detector_str,
                        region=aws_region,
                        account=account
                    ))

                    detector_id = detector_str

                master_detector_id = master_detector_id_dict[aws_region]
                member_dict = get_master_members(msession, aws_region, master_detector_id)
                print("Debug: member_dict {}".format(member_dict))

                # If detector is not a member of the GuardDuty master account, add it
                if account not in member_dict:
                    print("Debug: If detector is not a member of the GuardDuty master account, add it")
                    gd_client = msession.client('guardduty', region_name=aws_region)
                    print("Debug: gd_client {}".format(gd_client))
                    try:
                        print("Debug: Creating members")
                        gd_client.create_members(
                            AccountDetails=[
                                {
                                    'AccountId': account,
                                    'Email': aws_account_dict[account]
                                }
                            ],
                            DetectorId=master_detector_id
                        )
                    except ClientError as e:
                        print("Error: {}".format(e))
                    
                    print('Added Account {monitored} to member list in GuardDuty master account {master} for region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                    start_time = int(time.time())
                    while account not in member_dict:
                        if (int(time.time()) - start_time) > 100:
                            print("Membership did not show up for account {}, skipping".format(account))
                            break

                        time.sleep(5)
                        member_dict = get_master_members(msession, aws_region, master_detector_id)

                else:

                    print('Account {monitored} is already a member of {master} in region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                # Check if Verification Was failed before, delete and add it again.
                if member_dict[account] == 'EmailVerificationFailed':
                    # Member is enabled and already being monitored
                    print('Account {account} Error: EmailVerificationFailed'.format(account=account))
                    gd_client = msession.client('guardduty', region_name=aws_region)
                    gd_client.disassociate_members(
                        AccountIds=[
                            account
                        ],
                        DetectorId=master_detector_id
                    )

                    gd_client.delete_members(
                        AccountIds=[
                            account
                        ],
                        DetectorId=master_detector_id
                    )

                    print('Deleting members for {account} in {region}'.format(
                        account=account,
                        region=aws_region
                    ))

                    gd_client.create_members(
                        AccountDetails=[
                            {
                                'AccountId': account,
                                'Email': aws_account_dict[account]
                            }
                        ],
                        DetectorId=master_detector_id
                    )

                    print('Added Account {monitored} to member list in GuardDuty master account {master} for region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                    start_time = int(time.time())
                    while account not in member_dict:
                        if (int(time.time()) - start_time) > 300:
                            print("Membership did not show up for account {}, skipping".format(account))
                            break

                        time.sleep(5)
                        member_dict = get_master_members(msession, aws_region, master_detector_id)


                if member_dict[account] == 'Enabled':
                    # Member is enabled and already being monitored
                    print('Account {account} is already enabled'.format(account=account))

                else:
                    master_gd_client = msession.client('guardduty', region_name=aws_region)
                    gd_client = session.client('guardduty', region_name=aws_region)

                    if member_dict[account] == 'Disabled' :
                        # Member was disabled
                        print('Account {account} Error: Disabled'.format(account=account))
                        master_gd_client.start_monitoring_members(
                            AccountIds=[
                                account
                            ],
                            DetectorId=master_detector_id
                        )
                        print('Account {account} Re-Enabled'.format(account=account))

                    while member_dict[account] != 'Enabled':

                        if member_dict[account] == 'Created' :
                            # Member has been created in the GuardDuty master account but not invited yet
                            master_gd_client = msession.client('guardduty', region_name=aws_region)

                            master_gd_client.invite_members(
                                AccountIds=[
                                    account
                                ],
                                DetectorId=master_detector_id,
                                Message=gd_invite_message
                            )

                            print('Invited Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                monitored=account,
                                master=master_account,
                                region=aws_region
                            ))

                        if member_dict[account] == 'Invited' or member_dict[account] == 'Resigned' :
                            # member has been invited so accept the invite

                            response = gd_client.list_invitations()

                            invitation_dict = dict()

                            invitation_id = None
                            for invitation in response['Invitations']:
                                invitation_id = invitation['InvitationId']

                            if invitation_id is not None:
                                gd_client.accept_invitation(
                                    DetectorId=detector_id,
                                    InvitationId=invitation_id,
                                    MasterId=str(master_account)
                                )
                                print('Accepting Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                    monitored=account,
                                    master=master_account,
                                    region=aws_region
                                ))

                        # Refresh the member dictionary
                        member_dict = get_master_members(msession, aws_region, master_detector_id)

                    print('Finished {account} in {region}'.format(account=account, region=aws_region))

        except ClientError as e:
            print("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })
            raise

    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            print("{}: \n\t{}".format(
                list(account.keys())[0],
                account[list(account.keys())[0]]
            ))
            print("---------------------------------------------------------------")
    else:
        is_guardduty_enabled = True
    event['is_guardduty_enabled'] = is_guardduty_enabled
    return event