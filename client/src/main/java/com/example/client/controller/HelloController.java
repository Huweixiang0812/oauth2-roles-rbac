package com.example.client.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;

@RestController
@Slf4j
public class HelloController {
    @Resource
    private RestTemplate restTemplate;

    @GetMapping("/token")
    public String token(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient.getAccessToken().getTokenValue();
    }

    @GetMapping("/product")
    public String product(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue());
        HttpEntity<String> request = new HttpEntity<>("Product", headers);
        ResponseEntity<String> exchange = restTemplate.exchange("http://res-server:8081/products", HttpMethod.GET, request, String.class);
        String result = exchange.getBody();
        return result;
    }
}