package com.bss.sample.controller;

import com.bss.sample.model.UserAccount;
import com.bss.security.core.service.JwtTokenService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // In a real app, use AuthenticationManager. Here we simplify for the sample.
        try {
            UserDetails user = userDetailsService.loadUserByUsername(request.getUsername());
            
            // Password check (simple check for the sample)
            if (user.getPassword().equals("{noop}" + request.getPassword())) {
                String accessToken = jwtTokenService.generateToken(
                        user.getUsername(),
                        user.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList())
                );
                
                var refreshToken = jwtTokenService.createRefreshToken(user.getUsername());
                
                return ResponseEntity.ok(Map.of(
                        "accessToken", accessToken,
                        "refreshToken", refreshToken.getToken(),
                        "expiresIn", 3600
                ));
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
        }
    }

    @Data
    public static class LoginRequest {
        private String username;
        private String password;
    }
}
