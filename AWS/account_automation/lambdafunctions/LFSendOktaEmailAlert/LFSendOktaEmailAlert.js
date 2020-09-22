var aws = require('aws-sdk');
var sns = new aws.SNS();

exports.handler = (event, context, callback) => {

    aws.config.update({region: process.env.ExecutionRegion});
    event.message = "A new AWS account has been provisioned and pending final Okta integration. Please follow the steps below:" + "\n\n"
    + "1.	Input " + event.account_id + " under the Connected Accounts IDs (Applications < AWS App < Provisioning < Integration) for Okta Dev and Prod." + "\n"
    + "2.	Run Ansible playbook 'IAM – Okta Mapping' for Okta Dev and Prod." + "\n";

    event.subject = "New AWS account " + event.account_name + " Pending - Run Okta Ansible Automation";

    var params = {
        Message: event.message,
        Subject: event.subject,
        TopicArn: "arn:aws:sns:" + process.env.ExecutionRegion + ":" + process.env.ExecutionAccountId + ":SNSTopicForNewAccountOktaAlert"
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