package com.pds.capgroup.serviceNowConfig.models;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Builder
public class ServiceNowRequest
{
    private String caller_id;
    private String business_service;
    private String category;
    private String contact_type;
    private String assignment_group;
    private String short_description;
    private String assigned_to;
    private String impact;
    private String cmdb_ci;
    private String template;
}
