from __future__ import print_function
import json
import os
import boto3
import logging
import time
import datetime
import dateutil.tz

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

    expiry_tag = 'exp-date'
    all_instances = []
    try:
        instances = []
        ec2 = boto3.resource('ec2')
        if 'detail' in event:
            logger.info('This is a cloudwatch event. Update all EC2 instances as part of this event.')
            detail = event['detail']
            items = detail['responseElements']['instancesSet']['items']
            for item in items:
                instance = ec2.Instance(item['instanceId'])
                instances.append(instance)
            instances = instances.filter(Filters=[{'Name': 'tag-key', 'Values':[expiry_tag]}])
        else:
            logger.info('This is not a cloudwatch event. Do bulk update of all EC2 instances within this region.')
            #filter for instances with the correct tag
            instances = ec2.instances.filter(Filters=[{'Name': 'tag-key', 'Values':[expiry_tag]}])
        #grab the expiry string and get a list of instances with default date for expiry
        for instance in instances:
            for tag in instance.tags:
                if tag['Key'] == expiry_tag:
                    logger.info(instance)
                    logger.info(tag['Value'])
                    if '9999' in tag['Value']:
                        all_instances.append(instance.id)
        logger.info(all_instances)
        # Update all instances with default expiry date to a future expiry date.
        if all_instances:
            pacific = dateutil.tz.gettz('US/Pacific')
            days_out = os.environ['DAYS_OUT']
            days_forward_date = datetime.datetime.now(tz=pacific) + datetime.timedelta(days = days_out)
            formatted_date = f"{days_forward_date:%m}" + "-" + f"{days_forward_date:%d}" + "-" + str(days_forward_date.year)
            logger.info(formatted_date)
            for instanceid in all_instances:
                logger.info('Tagging resource ' + instanceid)
            ec2.create_tags(Resources=all_instances, Tags=[{'Key': expiry_tag, 'Value': formatted_date}])
        return True
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        return False