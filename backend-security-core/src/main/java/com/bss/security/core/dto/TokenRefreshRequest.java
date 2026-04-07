package com.bss.security.core.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshRequest {
    @Schema(description = "The refresh token string provided during login or previous refresh", example = "a2c3b4-d5e6-f7g8...")
    private String refreshToken;
}
