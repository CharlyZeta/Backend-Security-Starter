package com.bss.security.core;

import com.bss.security.core.service.JwtTokenService;
import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = TestSecurityApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits",
        "bss.security.cache.enabled=true"
})
class SecurityCacheTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenService jwtTokenService;

    @SpyBean
    private UserDetailsService userDetailsService;

    @Test
    @DisplayName("GIVEN cache enabled WHEN multiple requests THEN userDetailsService called only once")
    void givenCacheEnabled_whenMultipleRequests_thenUserDetailsServiceCalledOnce() throws Exception {
        String token = jwtTokenService.generateToken("userTest", Collections.singletonList("ROLE_USER"));

        // First request
        mockMvc.perform(get("/api/test")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Second request
        mockMvc.perform(get("/api/test")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Verify that userDetailsService.loadUserByUsername was called only once
        verify(userDetailsService, times(1)).loadUserByUsername("userTest");
    }
}
