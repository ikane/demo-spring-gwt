package org.ikane.demospringjwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyApi {
    @GetMapping("/hello")
    public String sayHello() {
        return "hello";
    }
}
