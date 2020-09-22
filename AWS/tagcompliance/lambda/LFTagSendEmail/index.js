var aws = require('aws-sdk');
exports.handler = (event, context, callback) => {

    if (event.finalResourceIDArray.length === 0) {
        callback(null,event);
    } else {
        var sesregion="";
        if (process.env.ExecutionRegion === "us-west-1") {
            sesregion="us-west-2";
        } else if (process.env.ExecutionRegion === "us-east-2") {
            sesregion="us-east-1";
        } else {
            sesregion=process.env.ExecutionRegion;
        }
        var ses = new aws.SES({region: sesregion});
    
        event.resources = "<b>AWS Account Alias: " + event.accountname + "<\/b><br><b>AWS Account: " + process.env.ExecutionAccountId + "<\/b><br><b>Region: " + process.env.ExecutionRegion + "<\/b><br>";
        for(var i=0; i < event.finalResourceIDArray.length; i++){
              event.resources =  event.resources + "<br>" 
              + "ResourceName: " + event.finalResourceIDArray[i] + "<br>"
              + "EventName: " + event.AllResourceEventName[i] + "<br>" 
              + "Username: " + event.AllResourceUsername[i] + "<br>";
        }
        var params = {
            Destination: {
                ToAddresses: [process.env.Email_Distribution]
            },
            Message: {
                Body: {
                    Html: { 
                        Charset: "UTF-8",
                        Data: event.resources
                    }
                },
                Subject: { Data: "Resource flagged for tagging non-compliance"
                }
            },
            Source: "shnc@capgroup.com"
        };
        ses.sendEmail(params, (err, data) => {
            if (err) {
                console.log(err);
                context.fail(err);
            } else {
                console.log(data);
                callback(null,event);
            }
        });
    }
};