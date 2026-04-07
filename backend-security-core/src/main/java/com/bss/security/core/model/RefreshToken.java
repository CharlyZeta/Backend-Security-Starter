package com.bss.security.core.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Model representing a Refresh Token.
 * It is decoupled from any specific persistence technology.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    private String token;
    private String username;
    private Instant expiryDate;
}
