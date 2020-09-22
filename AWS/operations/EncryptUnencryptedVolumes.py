from __future__ import print_function
import boto3
import botocore
import json
import time

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

def get_encryption_key_id(availabilityZone):
    response = ''
    regiondict = {'us-west-1c':'us-west-1','us-west-1b':'us-west-1','us-west-1a':'us-west-1', 'us-west-2c':'us-west-2','us-west-2b':'us-west-2','us-west-2a':'us-west-2','us-east-1c':'us-east-1','us-east-1b':'us-east-1','us-east-1a':'us-east-1', 'us-east-2c':'us-east-2','us-east-2b':'us-east-2','us-east-2a':'us-east-2'}
    deployregion = regiondict[availabilityZone]
    client = boto3.client('ec2',
        region_name=deployregion
    )
    try:
        response = client.get_ebs_default_kms_key_id(
            DryRun=False
        )
        #print(response)
    except Exception as e:
        print("Error creating snapshot. Error : {}".format(e))
    finally:
        return response 

def unencrypted_ebs_volumes(credentials,memberAccount):
    response = ''
    query = "SELECT\n" + \
          "accountId,\n" + \
          "resourceId,\n" + \
          "resourceType,\n" + \
          "resourceCreationTime,\n" + \
          "configuration.volumeType,\n" + \
          "tags,\n" + \
          "configuration.availabilityZone,\n" + \
          "configuration.attachments\n" + \
        "WHERE\n" + \
          "resourceType = 'AWS::EC2::Volume'\n" + \
          "AND configuration.encrypted = 'false'\n" + \
          "AND accountId = '" + memberAccount + "'"
  
    print(query)
    client = boto3.client('config',
        region_name='us-east-1',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    try:
        response = client.select_aggregate_resource_config(
            ConfigurationAggregatorName='OrgConfigurationAggregator',
            Limit=50,
            Expression=query
        )
        #print(response)
    except botocore.exceptions.ClientError as e:
        print("Error listing unencrypted ebs volumes. Error : {}".format(e))
        raise
    finally:
        return response        

def create_snapshot(volumeid,availabilityZone,tags):
    response = ''
    volumeregions = ["us-west-1a","us-east-1","us-west-2","us-east-2"]
    regiondict = {'us-west-1c':'us-west-1','us-west-1b':'us-west-1','us-west-1a':'us-west-1', 'us-west-2c':'us-west-2','us-west-2b':'us-west-2','us-west-2a':'us-west-2','us-east-1c':'us-east-1','us-east-1b':'us-east-1','us-east-1a':'us-east-1', 'us-east-2c':'us-east-2','us-east-2b':'us-east-2','us-east-2a':'us-east-2'}
    deployregion = regiondict[availabilityZone]
    client = boto3.client('ec2',
        region_name=deployregion
    )
    try:
        description = 'volume snapshot for ' + volumeid
        print(description)
        response = client.create_snapshot(
            Description=description,
            VolumeId=volumeid,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': str(k), 'Value': str(v)} for k, v in tags.items()
                    ]
                },
            ],
            DryRun=False
        )
        #print(response)
    except Exception as e:
        print("Error creating snapshot. Error : {}".format(e))
    finally:
        return response 


def create_encrypted_volume_from_snapshot(snapshotid,volumeType,tags,availabilityZone,encryption_key_id):
    response = ''
    #encryptionkeysdict = {'us-west-1':'alias/aws-ftdev-dev/uswest1/volfinal/0/kek','us-west-2':'alias/aws-ftdev-dev/uswest2/volfinal/0/kek','us-east-1':'alias/aws-ftdev-dev/useast1/volfinal/0/kek3','us-east-2':'alias/aws-ftdev-dev/useast2/volfinal/0/kek'}
    #encryptionkeysdict = {'us-west-1':'229c1e16-3ffa-4996-bea4-6b49020aad36','us-west-2':'7a33c571-ff4f-4fce-999a-2cd98907a372','us-east-1':'aws-ftdev-dev/useast1/volfinal/0/kek','us-east-2':'aws-ftdev-dev/useast2/volfinal/0/kek9'}
    regiondict = {'us-west-1c':'us-west-1','us-west-1b':'us-west-1','us-west-1a':'us-west-1', 'us-west-2c':'us-west-2','us-west-2b':'us-west-2','us-west-2a':'us-west-2','us-east-1c':'us-east-1','us-east-1b':'us-east-1','us-east-1a':'us-east-1', 'us-east-2c':'us-east-2','us-east-2b':'us-east-2','us-east-2a':'us-east-2'}
    deployregion = regiondict[availabilityZone]
    #encryptionkey = encryptionkeysdict[deployregion]
    
    #Check if snapshot is ready
    ec2 = boto3.resource('ec2')
    snapshot_available = False
    while snapshot_available is False:
        snapshot_state = ec2.Snapshot(snapshotid).state
        if snapshot_state != "completed":
            time.sleep(30)
            print(snapshot_state)
        else:
            snapshot_available = True

    client = boto3.client('ec2',
        region_name=deployregion
    )
    try:
        response = client.create_volume(
            AvailabilityZone=availabilityZone,
            Encrypted=True,
            KmsKeyId=encryption_key_id,
            SnapshotId=snapshotid,
            VolumeType=volumeType,
            DryRun=False,
            TagSpecifications=[
                {
                    'ResourceType': 'volume',
                    'Tags': [
                        {'Key': str(k), 'Value': str(v)} for k, v in tags.items()
                    ]
                },
            ]
        )
        #print(response)
    except Exception as e:
        print("Error creating encrypted volume from snapshot. Error : {}".format(e))
    finally:
        return response 

def lambda_handler(event,context):
    print(event)
    snapshot_list = []

    #Assume role of organization account to access advanced query within AWS Config
    masterAccount = '848721808596'
    account_role = 'OrganizationsReadAccessRole'
    credentials = assume_role(masterAccount, account_role)

    #memberAccount = '618057381738'
    memberAccount = event['member_account']
    response = unencrypted_ebs_volumes(credentials,memberAccount)

    results = response['Results']
    length = len(results)
    for i in range(length):
        response_json = json.loads(results[i])
        # print(response_json)
        volumeid = response_json['resourceId']
        volumeType = response_json['configuration']['volumeType']
        availabilityZone = response_json['configuration']['availabilityZone']
        tags = response_json['tags']
        existing_tags = {i['key']: i['value'] for i in tags}
        instanceId = response_json['configuration']['attachments'][0]['instanceId']
        device = response_json['configuration']['attachments'][0]['device']
        additional_tags = {
                "instance-id":instanceId,
                "device":device,
                "volume-id":volumeid
        }
        new_tags = {**existing_tags, **additional_tags}
        #print(new_tags)
        response = create_snapshot(volumeid,availabilityZone,new_tags)
        individual_snapshot_req = {}
        individual_snapshot_req['snapshotid'] = response['SnapshotId']
        individual_snapshot_req['volumeType'] = volumeType
        individual_snapshot_req['new_tags'] = new_tags
        individual_snapshot_req['availabilityZone'] = availabilityZone
        print(individual_snapshot_req)
        #new_individual_snapshot_req = dictionary(individual_snapshot_req)
        snapshot_list.append(individual_snapshot_req)
    print(snapshot_list)
    time.sleep(60)
    
    length = len(snapshot_list)
    for i in range(length):
        individual_snapshot_req = snapshot_list[i]
        snapshotid = individual_snapshot_req['snapshotid']
        volumeType = individual_snapshot_req['volumeType']
        new_tags = individual_snapshot_req['new_tags']
        availabilityZone = individual_snapshot_req['availabilityZone']
        response_dict = get_encryption_key_id(availabilityZone)
        encryption_key_id = response_dict['KmsKeyId']
        response = create_encrypted_volume_from_snapshot(snapshotid,volumeType,new_tags,availabilityZone,encryption_key_id)
        time.sleep(5)