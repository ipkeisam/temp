package com.pds.capgroup.serviceNowConfig.controllers;

import com.pds.capgroup.serviceNowConfig.clients.ServiceNowClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ServiceNowController {

    private final ServiceNowClient serviceNowClient = new ServiceNowClient();

    @PostMapping("/webhook")
    public String webhook() {
        return serviceNowClient.createTicket();
    }
}
