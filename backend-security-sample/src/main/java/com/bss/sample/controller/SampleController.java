package com.bss.sample.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class SampleController {

    @GetMapping("/public/info")
    public Map<String, String> getPublicInfo() {
        return Map.of(
                "status", "UP",
                "message", "This is a public endpoint"
        );
    }

    @GetMapping("/user/profile")
    public Map<String, Object> getUserProfile(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "message", "This is a PROTECTED endpoint for users"
        );
    }

    @GetMapping("/admin/dashboard")
    public Map<String, String> getAdminDashboard() {
        return Map.of(
                "message", "Welcome to the Admin Dashboard!"
        );
    }
}
