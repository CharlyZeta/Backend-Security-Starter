package com.bss.security.core;

import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecuritySecretStrengthTest {

    @Test
    @DisplayName("GIVEN a weak secret WHEN application starts THEN fail fast")
    void givenWeakSecret_whenAppStarts_thenFailFast() {
        SpringApplication app = new SpringApplication(TestSecurityApp.class);
        app.setDefaultProperties(Collections.singletonMap("bss.security.jwt.secret", "short-secret"));

        assertThrows(Exception.class, app::run, "Application should fail to start with a weak secret");
    }
}
