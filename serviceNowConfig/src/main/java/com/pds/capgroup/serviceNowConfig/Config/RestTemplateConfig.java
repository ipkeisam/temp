package com.pds.capgroup.serviceNowConfig.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@Configuration
public class RestTemplateConfig
{

    @Bean
    public RestTemplate restTemplate()
    {
        return new RestTemplate();
    }
}
