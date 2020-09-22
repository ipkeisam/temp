from __future__ import print_function
import json

def lambda_handler(event,context):
    
    print(event)
    message = event['Records'][0]['Sns']['Message']
    print(message)
    data = json.loads(message)
    print(data['RequestType'])