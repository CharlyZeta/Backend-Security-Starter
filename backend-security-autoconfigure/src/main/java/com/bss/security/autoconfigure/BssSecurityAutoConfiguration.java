package com.bss.security.autoconfigure;

import com.bss.security.core.config.BssSecurityConfig;
import com.bss.security.core.config.JwtAuthenticationEntryPoint;
import com.bss.security.core.controller.BssAuthController;
import com.bss.security.core.controller.BssManagementController;
import com.bss.security.core.filter.JwtAuthenticationFilter;
import com.bss.security.core.repository.InMemoryRefreshTokenRepository;
import com.bss.security.core.repository.RefreshTokenRepository;
import com.bss.security.core.service.JwtTokenService;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import(BssSecurityConfig.class)
public class BssSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenRepository refreshTokenRepository() {
        return new InMemoryRefreshTokenRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService(
            @org.springframework.beans.factory.annotation.Value("${bss.security.jwt.secret}") String secret,
            @org.springframework.beans.factory.annotation.Value("${bss.security.jwt.expiration:3600}") long expiration,
            @org.springframework.beans.factory.annotation.Value("${bss.security.jwt.refresh.expiration:604800}") long refreshExpiration,
            RefreshTokenRepository refreshTokenRepository) {
        return new JwtTokenService(secret, expiration, refreshExpiration, refreshTokenRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenService jwtTokenService, 
                                                         org.springframework.security.core.userdetails.UserDetailsService userDetailsService,
                                                         com.bss.security.core.config.BssCacheProperties cacheProperties) {
        return new JwtAuthenticationFilter(jwtTokenService, userDetailsService, cacheProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public BssAuthController bssAuthController(JwtTokenService jwtTokenService,
                                               org.springframework.security.core.userdetails.UserDetailsService userDetailsService) {
        return new BssAuthController(jwtTokenService, userDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public BssManagementController bssManagementController() {
        return new BssManagementController();
    }

    @Bean
    @ConditionalOnMissingBean
    public com.bss.security.core.service.RefreshTokenCleanupTask refreshTokenCleanupTask(JwtTokenService jwtTokenService) {
        return new com.bss.security.core.service.RefreshTokenCleanupTask(jwtTokenService);
    }

    @Bean
    @ConditionalOnMissingBean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(
                        new Components()
                                .addSecuritySchemes(securitySchemeName,
                                        new SecurityScheme()
                                                .name(securitySchemeName)
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")
                                )
                );
    }
}
