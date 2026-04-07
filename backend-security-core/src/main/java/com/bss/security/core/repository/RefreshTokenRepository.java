package com.bss.security.core.repository;

import com.bss.security.core.model.RefreshToken;

import java.util.Optional;

/**
 * Contract for Refresh Token persistence.
 * Third parties can implement this using JPA, Redis, MongoDB, etc.
 */
public interface RefreshTokenRepository {
    Optional<RefreshToken> findByToken(String token);
    RefreshToken save(RefreshToken refreshToken);
    void deleteByUsername(String username);
}
