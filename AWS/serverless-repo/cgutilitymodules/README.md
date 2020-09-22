# utility-modules

This project contains source code and supporting files for a serverless application that is deployed to the organization servereless appl repository using SAM CLI. It includes the following files and folders.

- utilitymodules.py - Code for the utility merge mandatory tags Lambda Layer.
- template.yaml - A template that defines the application's AWS resources.

The application uses several AWS resources, including a Lambda function, Default log group with 14 day expiry and an execution role for the lambda function. These resources are defined in the `template.yaml` file in this project. 

## Pre-requisites

1. The lambda layer requires permission to invoke organizations.list_tags_for_resource() when invoking merge_mandatory_tags
2. The lambda layer requires permission to invoke organizations.list_children() when invoking list_all_accounts
3. Any lambda function that uses any method which ends with _from_master using this layer will also require its role to allow access to   
   assume OrganizationsReadAccessRole of master account (848721808596) within its policy

## Input and Output

This lambda layer has the following method(s)
1. merge_mandatory_tags(old_tags,account_id) 
    Required parameters as input in the below order
    a) old_tags - existing tags available for a given resource to be tagged with the mandatory 7 tags
    b) account_id - The AWS account id where the resource is provisioned

    Output returned by the function in the below order
    a) tag merge status (boolean) 
    b) final set of tags to be applied to resource (dictionary)

2. list_all_accounts() 
    Required parameters as input in the below order - None
    
    This module will list all AWS accounts within the organization
    Will traverse the sub OUs upto a level of 2
    it will list account ids for accounts directly within root id
    and accounts within OUs (e.g CGUSER) beneath root
    and accounts within CGUSER (e.g PRD) 

    Output returned by the function in the below order
    a) list of all accounts (list) 

3. merge_mandatory_tags_from_master(old_tags,account_id)
    This method is invoked from any member account
    Required parameters as input in the below order
    a) old_tags - existing tags available for a given resource to be tagged with the mandatory 7 tags
    b) account_id - The AWS account id where the resource is provisioned

    Output returned by the function in the below order
    a) tag merge status (boolean) 
    b) final set of tags to be applied to resource (dictionary)

4. list_all_accounts_from_master()
    This method is invoked from any member account
    Required parameters as input - None
   
    This module will list all AWS accounts within the organization
    Will traverse the sub OUs upto a level of 2
    it will list account ids for accounts directly within root id
    and accounts within OUs (e.g CGUSER) beneath root
    and accounts within CGUSER (e.g PRD) 

    Output returned by the function in the below order
    a) list of all accounts (list) 

5. list_accounts_by_ou(ou_id)
    This method is invoked from the master account
    Required parameters as input - 
    b) ou_id - The OU to list the accounts within

    This module will list all AWS accounts within an organization OU (e.g PRD)
    Will traverse the sub OUs upto a level of 2

    Output returned by the function in the below order
    a) list of accounts within a given OU (list) 

6. list_accounts_by_ou_from_master(ou_id)
    This method is invoked from any member account
    Required parameters as input - 
    b) ou_id - The OU to list the accounts within

    This module will list all AWS accounts within an organization OU (e.g PRD)
    Will traverse the sub OUs upto a level of 2

    Output returned by the function in the below order
    a) list of accounts within a given OU (list) 

## Deploying this application from serverless appl repository

From the console 
1. Go to lambda console within any of the 4 US regions
2. Select "Browse serverless app repository"
3. Tab onto "Private applications" and select "CGUtilityModules" and follow instructions to Deploy
The Serverless Application Model Command Line Interface (SAM CLI) is an extension of the AWS CLI that adds functionality for building and testing Lambda applications. It uses Docker to run your functions in an Amazon Linux environment that matches Lambda. It can also emulate your application's build environment and API.


## Resources

AWS Serverless Application Repository : [AWS Serverless Application Repository main page](https://aws.amazon.com/serverless/serverlessrepo/