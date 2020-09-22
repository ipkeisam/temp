# GuardDuty

Use these templates and lambda to deploy GuardDuty across all accounts


### Installing

	MasterAccountGuardDutyRole.json to SecFoundation Account, this is used by lambda function
	MemberAccountGuardDutyRole.json from CapGroup Account to other accounts as stack sets to establish turst b.w master and member
    EnableGuardDuty lambda to SecFoundation Account (use role create from step1, keep 5min timeout)
	lambda_deploy.yaml:	deploys _function from s3 bucket (pre-req: function must be uploaded or already present on s3)


