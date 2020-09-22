import requests
import json
import logging
import base64

logger = logging.getLogger()
logger.setLevel(logging.INFO)

success_responseData = {
    "Status" : "SUCCESS",
    "Reason" : "Approved",
    "UniqueId" : "ID1234",
    "Data" : "Owner approved the stack creation"
    }
def lambda_handler(event,context):
    logger.info(json.dumps(event))
    if event['queryStringParameters'] and 'waitUrl' in event['queryStringParameters']:
        wait_url=event['queryStringParameters']['waitUrl']
        decoded_url =base64.b64decode(wait_url);
        try:
            response = requests.put(decoded_url,
                                    data=json.dumps(success_responseData))
            logger.info("Successfully responded for waithandle")
        except Exception as e:
            logger.info("Failed executing HTTP request: {}".format(e.code))
        return {'statusCode':'200','body':'Successfully Approved'}
    else:
        return {'statusCode':'200','body':'No Stack wait url found'}