var aws = require('aws-sdk');
var sns = new aws.SNS();

exports.handler = (event, context, callback) => {

    aws.config.update({region: process.env.ExecutionRegion});
    event.message = "A new AWS account has been provisioned and following needs to be added to Splunk AWS Add-on." + "\n\n"
    + "1.	Setup a new input for Description for the new account." + "\n"
    + "2.	Setup a new input for Cloudwatch Events for the new account including all US regions in same input" + "\n"
    + "3.	Setup a new input for RDS Cloudwatch Events for the new account including all US regions in same input." + "\n"
    + "4.	Setup new inputs for S3 Access Logs for the new account for each US region." + "\n\n"
    + "See Reference" + "\n"
    + "https://confluence.capgroup.com/display/HCEA/Splunk+AWS+Add-On+Configuration " + "\n";

    event.subject = "New AWS account(" + event.account_id + ") " + event.account_name + " Pending - Splunk AWS Add-on setup";

    var params = {
        Message: event.message,
        Subject: event.subject,
        TopicArn: "arn:aws:sns:" + process.env.ExecutionRegion + ":" + process.env.ExecutionAccountId + ":SNSTopicForNewAccountSplunkAlert"
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