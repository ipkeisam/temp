### This script retrieves the 'arn' of openshift policies in AWS
### and attaches them to the provisioned iam openshift users
### 
### Reads in defaults/main.yml file 
### run by typing 'python attach_iampolicies.py'

import boto3
import yaml

client = boto3.client('iam')

#Read in default main.yml file 
file_path = '../defaults/main.yml'

#Open up variable file
config=yaml.load(open(file_path))

#Extract ec2-user and s3-user iam name from default main.yml file
ec2_username=config['openshift_iam_user']['ec2-user']['name']
s3_username=config['openshift_iam_user']['s3-user']['name']

#Extract policy name from default main.yml file
ec2_policy_name=config['openshift_aws_policy']['ec2-policy']['name']
s3_policy_name=config['openshift_aws_policy']['s3-policy']['name']



#Defined variables to store the arn
ec2_policy_arn=""
s3_policy_arn=""

#Query AWS for a list of policies
response = client.list_policies(
    Scope='Local',
    OnlyAttached=False,
)

#Iterate through and fetch the arn of ec2 & s3 policy
for a in response['Policies']:
    if a['PolicyName'].lower() == s3_policy_name:
        s3_policy_arn = a['Arn']
    if a['PolicyName'].lower() == ec2_policy_name:
        ec2_policy_arn = a['Arn']

print("s3",s3_policy_arn)
print("ec2", ec2_policy_arn)

#Attach policy to s3 user
response = client.attach_user_policy(
    UserName=s3_username,
    PolicyArn=s3_policy_arn
)

#Attach policy to ec2-user 
response = client.attach_user_policy(
    UserName=ec2_username,
    PolicyArn=ec2_policy_arn
)