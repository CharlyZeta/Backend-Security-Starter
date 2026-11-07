package com.bss.testfixtures;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

/** Tokens HS256 (los que emite BSS en modo local) para los tests de FEAT-0013. */
public final class TestTokens {

    public static final String SECRET = "esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits";

    private TestTokens() {
    }

    public static String hs256(String subject, String authority) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", List.of(authority))
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }
}
