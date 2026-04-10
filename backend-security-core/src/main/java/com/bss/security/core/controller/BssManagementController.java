package com.bss.security.core.controller;

import com.bss.security.core.exception.BssErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Management API for BSS Dashboard.
 * In a real production environment, you might want to use @RefreshScope or persist this configuration.
 * For this Starter, we provide a read-only endpoint and a simulated update endpoint as requested by the plan.
 */
@RestController
@RequestMapping("/api/bss")
@Tag(name = "BSS Management", description = "Management API for BSS configuration. Requires BSS_ADMIN role.")
@SecurityRequirement(name = "bearerAuth")
public class BssManagementController {

    @Value("${bss.security.jwt.expiration:3600}")
    private long currentExpiration;

    @Value("${bss.security.jwt.refresh.expiration:604800}")
    private long currentRefreshExpiration;

    @Operation(summary = "Get current security configuration")
    @ApiResponse(responseCode = "200", description = "Current security configuration")
    @ApiResponse(responseCode = "401", description = "Unauthorized", 
                 content = @Content(schema = @Schema(implementation = BssErrorResponse.class)))
    @ApiResponse(responseCode = "403", description = "Forbidden - Requires ROLE_BSS_ADMIN", 
                 content = @Content(schema = @Schema(implementation = BssErrorResponse.class)))
    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("jwtExpiration", currentExpiration);
        config.put("refreshExpiration", currentRefreshExpiration);
        config.put("leewaySeconds", 60); // Hardcoded in service
        config.put("status", "ACTIVE");
        return ResponseEntity.ok(config);
    }

    @Operation(summary = "Update security configuration (Simulated)")
    @PostMapping("/config")
    public ResponseEntity<Map<String, Object>> updateConfig(@RequestBody Map<String, Object> updates) {
        // In a real scenario, this would update a database or use Spring Cloud Config
        // For the starter's scope, we acknowledge the payload and return the simulated updated state.
        Map<String, Object> newConfig = new HashMap<>();
        newConfig.put("jwtExpiration", updates.getOrDefault("jwtExpiration", currentExpiration));
        newConfig.put("refreshExpiration", updates.getOrDefault("refreshExpiration", currentRefreshExpiration));
        newConfig.put("leewaySeconds", 60);
        newConfig.put("status", "UPDATED_REQUIRE_RESTART");
        return ResponseEntity.ok(newConfig);
    }
}
