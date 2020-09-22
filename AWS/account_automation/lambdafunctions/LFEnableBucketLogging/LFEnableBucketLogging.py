import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def enable_logging(bucketname,targetbucket):

    is_bucket_logging_enabled = False
    client = boto3.client('s3')
    try:
        response = client.put_bucket_logging(
            Bucket=bucketname,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': targetbucket,
                    'TargetPrefix': bucketname
                }
            },
        )
        logger.info(response)
        is_bucket_logging_enabled = True
    except Exception as e:
        logger.error(e)
    finally:
        return is_bucket_logging_enabled

def lambda_handler(event, context):
    try:
        region = event['region']
        detail = event['detail']
        eventname = detail['eventName']

        logger.info('region: ' + str(region))
        logger.info('eventName: ' + str(eventname))
        logger.info('detail: ' + str(detail))

        if not detail['requestParameters']:
            logger.warning('No requestParameters found')
            if detail['errorCode']:
                logger.error('errorCode: ' + detail['errorCode'])
            if detail['errorMessage']:
                logger.error('errorMessage: ' + detail['errorMessage'])
            return False

        if eventname == 'CreateBucket':
            s3bucketname = detail['requestParameters']['bucketName']
            logger.info(s3bucketname)
        else:
            logger.warning('Not supported action')

        if s3bucketname:
            #Extract account id where the bucket is being created
            accountid = boto3.client('sts').get_caller_identity()['Account']

            #bucket name of the s3 access logging bucket
            targetbucket = "{0}-s3-access-logs-{1}".format(accountid,region)

            logger.info('accountid: ' + str(accountid))
            logger.info('targetbucket: ' + str(targetbucket))

            response = enable_logging(s3bucketname,targetbucket)
            logger.info(response)

    except Exception as e:
        logger.error('Error message: ' + str(e))