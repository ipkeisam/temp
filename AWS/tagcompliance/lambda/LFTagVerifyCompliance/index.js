const aws = require('aws-sdk'); 
const config = new aws.ConfigService(); 
var config_params = {
  ConfigRuleName: 'required-tags', /* required */
  ComplianceTypes: ['NON_COMPLIANT'],
  Limit: process.env.Resource_Limit
};

exports.handler = (event, context, callback) => {
    event.AllResourceEventName = [];
    event.AllResourceUsername = [];
    event.finalResourceIDArray = [];
    event.accountname = "Not Defined";
    config.getComplianceDetailsByConfigRule(config_params, (err, data) => {
      var resource_id = [];
      if (err) {
          return callback(err);
      }
      else {
        const resource_count = data.EvaluationResults.length;
        for(var i=0; i < resource_count; i++){
          var individual_resource = data.EvaluationResults[i].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId;
          resource_id.push(individual_resource);
        }
        event.resourceIDArray = resource_id;
        event.staticResourceIDArray = resource_id;
        if (event.resourceIDArray.length > 0) {
          event.has_elements = true;
          event.no_resources_to_tag = false;                    
        } else {
          event.has_elements = false;
          event.no_resources_to_tag = true;
        }
        callback(null,event);  
      }
    });  

};