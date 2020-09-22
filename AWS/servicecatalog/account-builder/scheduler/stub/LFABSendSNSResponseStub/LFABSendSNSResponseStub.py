from __future__ import print_function
import json
import requests

def sendTriggerSNSResponse(event, context, responseStatus, responseData):
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}
    print('RESPONSE BODY:n' + json.dumps(responseBody))
    try:
        req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return
    except requests.exceptions.RequestException as e:
        print(e)
        raise

def lambda_handler(event,context):
    
    print(event)
    message = event['Records'][0]['Sns']['Message']
    print(message)
    data = json.loads(message)

    if "ResponseURL" in data:
        responseStatus = 'SUCCESS'
        sendTriggerSNSResponse(data, context, responseStatus, {})