package org.ikane.demospringjwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class MyApi {
    @GetMapping("/hello")
    public String sayHello() {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

        log.info("connected user: {}", jwtAuthenticationToken.getName());
        log.info("uid-local claim: {}", jwtAuthenticationToken.getToken().getClaimAsString("uid-local"));
        return "hello";
    }
}
