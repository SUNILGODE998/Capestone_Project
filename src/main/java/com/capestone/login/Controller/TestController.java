package com.capestone.login.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/secure")
    public ResponseEntity<String> secureEndpoint() {
        return ResponseEntity.ok("Token is valid. Access granted!");
    }
}
