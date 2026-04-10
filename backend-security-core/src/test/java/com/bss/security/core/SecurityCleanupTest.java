package com.bss.security.core;

import com.bss.security.core.model.RefreshToken;
import com.bss.security.core.repository.RefreshTokenRepository;
import com.bss.security.core.service.JwtTokenService;
import com.bss.security.core.service.RefreshTokenCleanupTask;
import com.bss.security.core.testapp.TestSecurityApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(classes = TestSecurityApp.class)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits"
})
class SecurityCleanupTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenCleanupTask cleanupTask;

    @Test
    @DisplayName("GIVEN expired tokens WHEN cleanup task runs THEN tokens are removed")
    void givenExpiredTokens_whenCleanupRuns_thenRemoved() {
        // Manually save an expired token
        RefreshToken expiredToken = RefreshToken.builder()
                .username("userTest")
                .token("expired-token-123")
                .expiryDate(Instant.now().minusSeconds(3600)) // Expired 1 hour ago
                .build();
        refreshTokenRepository.save(expiredToken);

        // Verify it exists
        assertTrue(refreshTokenRepository.findByToken("expired-token-123").isPresent());

        // Run cleanup
        cleanupTask.cleanupExpiredTokens();

        // Verify it's gone
        assertTrue(refreshTokenRepository.findByToken("expired-token-123").isEmpty(), "Expired token should be cleaned up");
    }
}
