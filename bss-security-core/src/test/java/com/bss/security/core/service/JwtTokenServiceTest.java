package com.bss.security.core.service;

import com.bss.security.core.repository.InMemoryRefreshTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;
    private InMemoryRefreshTokenRepository refreshTokenRepository;
    private final String secret = "esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits";
    private final long expiration = 3600; // 1 hour
    private final long refreshExpiration = 604800; // 7 days

    @BeforeEach
    void setUp() {
        refreshTokenRepository = new InMemoryRefreshTokenRepository();
        jwtTokenService = new JwtTokenService(secret, expiration, refreshExpiration, refreshTokenRepository);
    }

    @Test
    @DisplayName("GIVEN a username and roles WHEN generate token THEN return a valid JWT")
    void givenUsernameAndRoles_whenGenerateToken_thenReturnValidJwt() {
        String token = jwtTokenService.generateToken("userTest", Collections.singletonList("ROLE_USER"));
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        String username = jwtTokenService.extractUsername(token);
        assertEquals("userTest", username);
    }

    @Test
    @DisplayName("GIVEN an expired token within leeway time WHEN validate THEN return true")
    void givenExpiredTokenWithinLeeway_whenValidate_thenReturnTrue() {
        // Generate a token that expired 30 seconds ago
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("userTest")
                .expiration(new Date(System.currentTimeMillis() - 30000)) // Expired 30s ago
                .signWith(key)
                .compact();

        assertTrue(jwtTokenService.validateToken(token, "userTest"));
    }

    @Test
    @DisplayName("GIVEN an expired token outside leeway time WHEN validate THEN return false")
    void givenExpiredTokenOutsideLeeway_whenValidate_thenReturnFalse() {
        // Generate a token that expired 90 seconds ago
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("userTest")
                .expiration(new Date(System.currentTimeMillis() - 90000)) // Expired 90s ago
                .signWith(key)
                .compact();

        assertFalse(jwtTokenService.validateToken(token, "userTest"));
    }
}
