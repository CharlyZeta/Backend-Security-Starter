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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = TestSecurityApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits"
})
class SecurityMultiSessionTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Test
    @DisplayName("GIVEN multiple sessions WHEN refresh one THEN others remain valid")
    void givenMultipleSessions_whenRefreshOne_thenOthersRemainValid() throws Exception {
        // Create two refresh tokens for the same user (simulating two devices)
        RefreshToken rt1 = jwtTokenService.createRefreshToken("userTest");
        RefreshToken rt2 = jwtTokenService.createRefreshToken("userTest");

        // Refresh token 1
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + rt1.getToken() + "\"}"))
                .andExpect(status().isOk());

        // Verify rt1 is now invalid (it was rotated)
        assertTrue(jwtTokenService.findByToken(rt1.getToken()).isEmpty(), "Old RT1 should be deleted");

        // Verify rt2 is STILL valid (it should NOT have been deleted)
        assertTrue(jwtTokenService.findByToken(rt2.getToken()).isPresent(), "RT2 should still exist");
        
        // Refresh token 2 to double check
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + rt2.getToken() + "\"}"))
                .andExpect(status().isOk());
    }
}
