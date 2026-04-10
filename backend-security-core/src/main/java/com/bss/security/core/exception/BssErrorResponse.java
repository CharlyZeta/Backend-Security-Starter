package com.bss.security.core.exception;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Standardized error response for BSS Security")
public class BssErrorResponse {
    @Schema(description = "HTTP Status Code", example = "401")
    private int status;
    @Schema(description = "Error type", example = "Unauthorized")
    private String error;
    @Schema(description = "Detailed error message", example = "Token is invalid or expired")
    private String message;
    @Schema(description = "Request path", example = "/api/test")
    private String path;
    @Schema(description = "Timestamp of the error")
    private LocalDateTime timestamp;
}
