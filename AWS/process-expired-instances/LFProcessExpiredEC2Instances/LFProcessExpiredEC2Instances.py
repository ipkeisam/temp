from __future__ import print_function
import boto3
import datetime
import sys
import dateutil.tz
import botocore
import os

def terminate_ec2_instance(expiredInstances):

    ec2 = boto3.resource('ec2')
    instances = ec2.instances.filter(InstanceIds=expiredInstances)
    try:
        response = instances.terminate(
            DryRun=True
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))
        
def send_expiry_alert(expiredInstances,date):
    region = os.environ['SNS_REGION']
    topicArn = os.environ['SNS_TOPIC_ARN']
    session = boto3.session.Session()
    sns_client = session.client(
                service_name='sns',
                region_name=region
            )
    try:
        #message = str(expiredInstances)
        message = '\n'.join(map(str, expiredInstances))
        subject = "Please take remedial action: EC2 instances with an expiry date - " + date
        response = sns_client.publish(
            TopicArn=topicArn,
            Message=message,
            Subject=subject
        )
    except botocore.exceptions.ClientError as e:
        print("Error : {}".format(e))

def lambda_handler(event, context):
    expired_instances = []
    expiry_tag = 'exp-date'
    all_instances = []
    #filter for instances with the correct tag
    ec2 = boto3.resource('ec2')
    instances = ec2.instances.filter(Filters=[{'Name': 'tag-key', 'Values':[expiry_tag]}])
    #grab the expiry string
    for instance in instances:
        for tag in instance.tags:
            if tag['Key'] == expiry_tag:
                all_instances.append({'instance':instance, 'expiry':tag['Value']})

    print(all_instances)
    pacific = dateutil.tz.gettz('US/Pacific')
    yesterday = datetime.datetime.now(tz=pacific) - datetime.timedelta(days = 1)
    formatted_date = f"{yesterday:%m}" + "-" + f"{yesterday:%d}" + "-" + str(yesterday.year)
    print(formatted_date)

    for instances in all_instances:
        expiry_date = instances['expiry']
        if formatted_date in expiry_date:
            expired_instances.append(instances['instance'].id)
    print(expired_instances)

    if expired_instances:
        print(expired_instances)
        #response = terminate_ec2_instance(expired_instances)
        #response = send_expiry_alert(expired_instances,formatted_date)