const aws = require('aws-sdk');
const cloudtrail = new aws.CloudTrail(); 
exports.handler = (event, context, callback) => {
    event.startDate = new Date();
    event.endDate = new Date();
    event.finalArrayisEmpty = false;
    event.startDate.setHours(event.startDate.getHours() - process.env.Reduce_Hours);
    const setLookupAttributes = {
        StartTime: event.startDate,
        EndTime: event.endDate,
        LookupAttributes: [{
            AttributeKey: 'ResourceName',
            AttributeValue: event.resourceIDArray.shift()
        }],
        MaxResults: 1
    };
    if (event.resourceIDArray.length > 0) {
        event.has_elements = true;
    } else {
        event.has_elements = false;
    }
    cloudtrail.lookupEvents(setLookupAttributes, (err, data) => {
        if (err) {
            return callback(err);
        }
        var resourceEventName = "";
        var resourceUsername = "";   
        if(data.Events.length > 0){
          event.resourceEventName = data.Events[0].EventName;
          event.resourceUsername = data.Events[0].Username;
          event.AllResourceEventName.push(event.resourceEventName);
          event.AllResourceUsername.push(event.resourceUsername);
          event.finalResourceIDArray.push(event.staticResourceIDArray.shift());
        } else{
          event.staticResourceIDArray.shift();
          event.resourceEventName = "Not Available";
          event.resourceUsername = "Not Available";            
        }
        if(event.finalResourceIDArray.length === 0)
          event.finalArrayisEmpty = true;
        callback(null,event);
    });  
};