var aws = require('aws-sdk');
var sns = new aws.SNS();

exports.handler = (event, context, callback) => {

    aws.config.update({region: process.env.ExecutionRegion});
    event.message = "New AWS Account Name: " + event.account_name + "\n\n"
    + "Account Environment Type:" + event.environment_type + "\n\n"
    + "Account Email:" + event.account_email + "\n\n"
    + "1. Governance IAM users/roles created successfully: " + event.is_iam_stack_created + "\n\n"
    + "2. Service Control policies applied successfully: " + event.is_scp_setup_complete + "\n\n"
    + "3. Account password policy applied successfully: " + event.is_password_policy_setup_complete + "\n\n"
    + "4. Okta IAM roles created successfully: " + event.is_okta_stack_created + "\n\n"
    + "5. Okta Dev provider created successfully: " + event.is_okta_dev_provider_created + "\n\n"
    + "6. Okta Prod provider created successfully: " + event.is_okta_prod_provider_created + "\n\n"
    + "7. IAM Automation account created successfully: " + event.is_iam_automation_user_created + "\n\n"
    + "8. IAM playbook invocation status: " + event.is_iam_playbook_invoked + "\n\n"
    + "9. IAM Vertical Access playbook invocation status: " + JSON.stringify(event.is_iam_va_playbook_invoked) + "\n\n"
    + "10. Cloudability enabled for the account: " + event.is_cloudability_stack_created + "\n\n"
    + "11. Qualys enabled for the account: " + JSON.stringify(event.QualysOutput) + "\n\n"
    + "12. Dome9 enabled for the account: " + event.isDome9onboarded + "\n\n"
    + "13. GuardDuty enabled for the account: " + event.is_guardduty_enabled + "\n\n"
    + "14. Baseline splunk resources created successfully: " + event.is_splunk_stack_created + "\n\n"
    + "15. Config Resources deployed successfully: " + event.is_configservice_stack_created + "\n\n"
    + "16. S3 Conformance Pack deployed successfully: " + JSON.stringify(event.are_s3conformancepacks_created) + "\n\n"
    + "17. ML Conformance Pack deployed successfully: " + JSON.stringify(event.are_mlconformancepacks_created) + "\n\n"
    + "18. Encryption Conformance Pack deployed successfully: " + JSON.stringify(event.are_encrptionconformancepacks_created) + "\n\n"
    + "19. Publicly Accessible Conformance Pack deployed successfully: " + JSON.stringify(event.are_paconformancepacks_created) + "\n\n"
    + "20. Tag Compliance Config Rules deployed successfully: " + JSON.stringify(event.are_tagconfigrules_created) + "\n\n"
    + "21. KMS module executed successfully: " + JSON.stringify(event.are_kms_keys_created) + "\n\n"
    + "22. Network module executed successfully: " + JSON.stringify(event.are_network_vpcs_created) + "\n\n"
    + "23. AWS account email distribution created successfully: " + event.is_email_distribution_created + "\n\n"
    + "24. Default EBS encryption executed successfully: " + JSON.stringify(event.default_ebs_encryption_successful) + "\n\n"
    + "25. S3 public access blocked successfully: " + event.is_s3_public_access_blocked + "\n\n"
    + "26. Created case to upgrade to Enterprise Support successfully: " + event.is_entsupport_ticket_opened + "\n\n"
    + "27. Account moved to appropriate OU: " + event.is_account_moved_to_ou;

    event.subject = "New member account provisioned:" + event.account_id;

    var params = {
        Message: event.message,
        Subject: event.subject,
        TopicArn: "arn:aws:sns:" + process.env.ExecutionRegion + ":" + process.env.ExecutionAccountId + ":SNSTopicForNewAccountAlerts"
    };
    var publishTextPromise = new aws.SNS({apiVersion: '2010-03-31'}).publish(params).promise();
    publishTextPromise.then(
      function(data) {
        console.log('Message ${params.Message} send sent to the topic ${params.TopicArn}');
        console.log("MessageID is " + data.MessageId);
      }).catch(
        function(err) {
        console.error(err, err.stack);
        callback(null,event);
    });
    callback(null,event);
};