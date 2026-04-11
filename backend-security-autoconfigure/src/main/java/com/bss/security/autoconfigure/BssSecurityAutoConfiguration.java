package com.bss.security.autoconfigure;

import com.bss.security.core.config.BssCacheProperties;
import com.bss.security.core.config.BssCorsProperties;
import com.bss.security.core.config.BssSecurityConfig;
import com.bss.security.core.config.JwtAuthenticationEntryPoint;
import com.bss.security.core.controller.BssAuthController;
import com.bss.security.core.controller.BssManagementController;
import com.bss.security.core.filter.JwtAuthenticationFilter;
import com.bss.security.core.repository.InMemoryRefreshTokenRepository;
import com.bss.security.core.repository.RefreshTokenRepository;
import com.bss.security.core.service.JwtTokenService;
import com.bss.security.core.service.RefreshTokenCleanupTask;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;

@AutoConfiguration
@Import(BssSecurityConfig.class)
@EnableConfigurationProperties({BssCacheProperties.class, BssCorsProperties.class})
public class BssSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenRepository refreshTokenRepository() {
        return new InMemoryRefreshTokenRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService(
            @Value("${bss.security.jwt.secret}") String secret,
            @Value("${bss.security.jwt.expiration:3600}") long expiration,
            @Value("${bss.security.jwt.refresh.expiration:604800}") long refreshExpiration,
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
                                                         UserDetailsService userDetailsService,
                                                         BssCacheProperties cacheProperties) {
        return new JwtAuthenticationFilter(jwtTokenService, userDetailsService, cacheProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public BssAuthController bssAuthController(JwtTokenService jwtTokenService,
                                               UserDetailsService userDetailsService) {
        return new BssAuthController(jwtTokenService, userDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public BssManagementController bssManagementController() {
        return new BssManagementController();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenCleanupTask refreshTokenCleanupTask(JwtTokenService jwtTokenService) {
        return new RefreshTokenCleanupTask(jwtTokenService);
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
