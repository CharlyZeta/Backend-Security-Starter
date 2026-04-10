package com.bss.security.core.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenCleanupTask {

    private final JwtTokenService jwtTokenService;

    @Scheduled(fixedDelayString = "${bss.security.cache.cleanup-interval-ms:3600000}")
    public void cleanupExpiredTokens() {
        log.info("Starting automatic cleanup of expired refresh tokens...");
        jwtTokenService.cleanExpiredTokens();
        log.info("Cleanup completed.");
    }
}
