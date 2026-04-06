package com.bss.security.core;

import com.bss.security.core.model.RefreshToken;
import com.bss.security.core.service.JwtTokenService;
import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = TestSecurityApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits",
        "bss.security.jwt.expiration=3600",
        "bss.security.jwt.refresh.expiration=604800"
})
class SecurityDefaultTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Test
    @DisplayName("GIVEN an unauthenticated request WHEN access any endpoint THEN return 401 Unauthorized")
    void givenUnauthenticatedRequest_whenAccessAnyEndpoint_thenReturn401() throws Exception {
        mockMvc.perform(get("/api/test"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GIVEN a valid token WHEN access a protected endpoint THEN return 200 OK")
    void givenValidToken_whenAccessProtectedEndpoint_thenReturn200() throws Exception {
        String token = jwtTokenService.generateToken("userTest", Collections.singletonList("ROLE_USER"));

        mockMvc.perform(get("/api/test")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Allowed!"));
    }

    @Test
    @DisplayName("GIVEN normal user token WHEN access management api THEN return 403 Forbidden")
    void givenNormalUser_whenAccessManagementApi_thenReturn403() throws Exception {
        String token = jwtTokenService.generateToken("userTest", Collections.singletonList("ROLE_USER"));

        mockMvc.perform(get("/api/bss/config")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GIVEN admin token WHEN access management api THEN return 200 OK")
    void givenAdminUser_whenAccessManagementApi_thenReturn200() throws Exception {
        String token = jwtTokenService.generateToken("adminTest", Collections.singletonList("ROLE_BSS_ADMIN"));

        mockMvc.perform(get("/api/bss/config")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @DisplayName("GIVEN valid refresh token WHEN request refresh THEN return new tokens")
    void givenValidRefreshToken_whenRequestRefresh_thenReturnNewTokens() throws Exception {
        RefreshToken refreshToken = jwtTokenService.createRefreshToken("userTest");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken.getToken() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }
}
