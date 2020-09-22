from __future__ import print_function
import boto3
import botocore
import requests
import json

def sendResponse(event, context, responseStatus, responseData):
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

def deploy_conformancepack(conformancepackname,deliverybucket,tempaltes3uri,deployregion):
    is_conformance_pack_created = False
    client = boto3.client('config',
                        region_name=deployregion)
    try:
        response = client.put_organization_conformance_pack(
            OrganizationConformancePackName=conformancepackname,
            TemplateS3Uri=tempaltes3uri,
            DeliveryS3Bucket=deliverybucket
        )
        print(response)
        is_conformance_pack_created = True
        return is_conformance_pack_created

    except botocore.exceptions.ClientError as e:
        print("Error deploying stack. Error : {}".format(e))
        return is_conformance_pack_created

def lambda_handler(event,context):
    print(event)
    responseData = {} 
    #aws configservice put-organization-conformance-pack --organization-conformance-pack-name S3BestPracticesConformancePack --delivery-s3-bucket awsconfigconforms-848721808596 
    conformancepackname = event['ResourceProperties']['ConformancePackName']
    deliverybucket = event['ResourceProperties']['DeliveryS3Bucket']
    tempaltes3uri = event['ResourceProperties']['TemplateS3URI']

    configregions = ["us-west-1","us-east-1","us-east-2","us-west-2"]

    #iterate through all 4 US regions to deploy template
    for deployregion in configregions:
        is_conformance_pack_created = deploy_conformancepack(conformancepackname,deliverybucket,tempaltes3uri,deployregion)
    responseData['is_conformance_pack_created'] = is_conformance_pack_created
    responseStatus = 'SUCCESS'
    print("Conformance Pack deployed successfully:"+ str(is_conformance_pack_created))
    sendResponse(event, context, responseStatus, responseData)