package com.messageapp.message.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @GetMapping("/find")
    public ResponseEntity<?> getUser() {
        return ResponseEntity.ok("Hello World");
    }
}
