package com.bss.security.core.controller;

import com.bss.security.core.dto.TokenRefreshRequest;
import com.bss.security.core.dto.TokenRefreshResponse;
import com.bss.security.core.exception.JwtValidationException;
import com.bss.security.core.model.RefreshToken;
import com.bss.security.core.service.JwtTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "BSS Auth operations including token refresh")
public class BssAuthController {

    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;

    @Operation(summary = "Refresh Access Token", description = "Provides a new JWT Access Token given a valid Refresh Token")
    @ApiResponse(responseCode = "200", description = "Successful token refresh")
    @ApiResponse(responseCode = "401", description = "Refresh token expired or invalid")
    @PostMapping("/refresh")
    public ResponseEntity<TokenRefreshResponse> refreshtoken(@RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return jwtTokenService.findByToken(requestRefreshToken)
                .map(jwtTokenService::verifyExpiration)
                .map(RefreshToken::getUsername)
                .map(username -> {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    
                    // Generate new access token
                    String token = jwtTokenService.generateToken(
                            userDetails.getUsername(), 
                            userDetails.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.toList())
                    );
                    
                    // Generate a new refresh token (Rotation)
                    RefreshToken newRefreshToken = jwtTokenService.createRefreshToken(username);

                    return ResponseEntity.ok(new TokenRefreshResponse(token, newRefreshToken.getToken()));
                })
                .orElseThrow(() -> new JwtValidationException("Refresh token is not in database!"));
    }
}
