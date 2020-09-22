var aws = require('aws-sdk');
var iam = new aws.IAM();

exports.handler = (event, context, callback) => {
    var params = {
    };
    iam.listAccountAliases(params, (err, data) => {
        if (err) {
            console.log(err, err.stack); 
            event.accountname = "Not Available";
            return callback(err);
        } else {
            event.accountname=data.AccountAliases[0];
            console.log("account alias:" + data.AccountAliases[0]);
            callback(null,event);
        }
    });
};