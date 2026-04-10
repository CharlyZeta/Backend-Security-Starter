package com.bss.security.core;

import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityInsecureCorsTest {

    @Test
    @DisplayName("GIVEN insecure CORS (wildcard + credentials) WHEN app starts THEN fail fast")
    void givenInsecureCors_whenAppStarts_thenFailFast() {
        SpringApplication app = new SpringApplication(TestSecurityApp.class);
        Map<String, Object> props = new HashMap<>();
        props.put("bss.security.jwt.secret", "esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits");
        props.put("bss.security.cors.enabled", "true");
        props.put("bss.security.cors.allow-credentials", "true");
        props.put("bss.security.cors.allowed-origins", "*");
        
        app.setDefaultProperties(props);

        assertThrows(Exception.class, app::run, "Application should fail with insecure CORS config");
    }
}
