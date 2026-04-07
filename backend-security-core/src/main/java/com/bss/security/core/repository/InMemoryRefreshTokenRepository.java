package com.bss.security.core.repository;

import com.bss.security.core.model.RefreshToken;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory implementation to allow the starter to work out-of-the-box.
 * For production environments, it is recommended to provide a persistent implementation.
 */
public class InMemoryRefreshTokenRepository implements RefreshTokenRepository {

    private final Map<String, RefreshToken> store = new ConcurrentHashMap<>();

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return Optional.ofNullable(store.get(token));
    }

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        store.put(refreshToken.getToken(), refreshToken);
        return refreshToken;
    }

    @Override
    public void deleteByUsername(String username) {
        store.entrySet().removeIf(entry -> entry.getValue().getUsername().equals(username));
    }
}
