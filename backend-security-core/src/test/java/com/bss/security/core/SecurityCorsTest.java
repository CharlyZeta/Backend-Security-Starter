package com.bss.security.core;

import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = TestSecurityApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits",
        "bss.security.cors.enabled=true",
        "bss.security.cors.allowed-origins=http://localhost:3000",
        "bss.security.cors.allowed-methods=GET,POST"
})
class SecurityCorsTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GIVEN CORS enabled WHEN preflight request THEN return CORS headers")
    void givenCorsEnabled_whenPreflight_thenReturnHeaders() throws Exception {
        mockMvc.perform(options("/api/test")
                        .header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
                .andExpect(header().string("Access-Control-Allow-Methods", "GET,POST"));
    }

    @Test
    @DisplayName("GIVEN CORS enabled WHEN request from unauthorized origin THEN return 403 Forbidden or no CORS headers")
    void givenCorsEnabled_whenForbiddenOrigin_thenReturnNoCORSHeaders() throws Exception {
        mockMvc.perform(options("/api/test")
                        .header("Origin", "http://forbidden.com")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }
}
