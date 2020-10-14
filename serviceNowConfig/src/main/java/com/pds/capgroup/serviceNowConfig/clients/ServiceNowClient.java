package com.pds.capgroup.serviceNowConfig.clients;

import com.pds.capgroup.serviceNowConfig.models.ServiceNowRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;

@Component
public class ServiceNowClient {

    @Value("${servicenow.url}")
    public String url;

    @Value("${servicenow.caller_id}")
    public String caller_id;

    @Value("${servicenow.business_service}")
    public String business_service;

    @Value("${servicenow.category}")
    public String category;

    @Value("${servicenow.contact_type}")
    public String contact_type;

    @Value("${servicenow.assignment_group}")
    public String assignment_group;

    @Value("${servicenow.short_description}")
    public String short_description;

    @Value("${servicenow.assigned_to}")
    public String assigned_to;

    @Value("${servicenow.impact}")
    public String impact;

    @Value("${servicenow.cmdb_ci}")
    public String cmdb_ci;

    @Value("${servicenow.template}")
    public String template;

    @Value("${servicenow.encodedAuth}")
    public String encodedAuth;

    @Autowired
    public RestTemplate restTemplate;

    private static final Logger logger = LoggerFactory.getLogger(ServiceNowClient.class);

    public String createTicket()
    {
        try
        {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/json");
            headers.add("Authorization", "Basic " + encodedAuth);

            HttpEntity<ServiceNowRequest> request = new HttpEntity<ServiceNowRequest>(ServiceNowRequest.builder()
                    .caller_id(caller_id)
                    .business_service(business_service)
                    .category(category)
                    .contact_type(contact_type)
                    .assignment_group(assignment_group)
                    .short_description(short_description)
                    .assigned_to(assigned_to)
                    .impact(impact)
                    .cmdb_ci(cmdb_ci)
                    .template(template)
                    .build(), headers);

            String serviceNowResponse = restTemplate.postForObject(url, request, String.class);

            String logMsg = String.format("Created ServiceNow incident:%n%s", serviceNowResponse);
            logger.info(logMsg);

            return serviceNowResponse;
        }
        catch (Exception e1)
        {
            String errorMsg = String.format("Failed to create ServiceNow Alert Ticket at %s!", url);
            logger.error(errorMsg, e1);
            return errorMsg;
        }
    }
}
