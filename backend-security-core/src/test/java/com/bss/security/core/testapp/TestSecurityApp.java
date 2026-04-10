package com.bss.security.core.testapp;

import com.bss.security.core.config.JwtAuthenticationEntryPoint;
import com.bss.security.core.filter.JwtAuthenticationFilter;
import com.bss.security.core.model.BssSecurityUserAdapter;
import com.bss.security.core.model.SecurityUser;
import com.bss.security.core.repository.InMemoryRefreshTokenRepository;
import com.bss.security.core.repository.RefreshTokenRepository;
import com.bss.security.core.service.JwtTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;

@SpringBootApplication(scanBasePackages = "com.bss.security.core")
public class TestSecurityApp {
    public static void main(String[] args) {
        SpringApplication.run(TestSecurityApp.class, args);
    }

    @Bean
    public RefreshTokenRepository refreshTokenRepository() {
        return new InMemoryRefreshTokenRepository();
    }

    @Bean
    public JwtTokenService jwtTokenService(
            @Value("${bss.security.jwt.secret}") String secret,
            @Value("${bss.security.jwt.expiration:3600}") long expiration,
            @Value("${bss.security.jwt.refresh.expiration:604800}") long refreshExpiration,
            RefreshTokenRepository refreshTokenRepository) {
        return new JwtTokenService(secret, expiration, refreshExpiration, refreshTokenRepository);
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenService jwtTokenService, UserDetailsService userDetailsService, com.bss.security.core.config.BssCacheProperties cacheProperties) {
        return new JwtAuthenticationFilter(jwtTokenService, userDetailsService, cacheProperties);
    }

    @Bean
    public com.bss.security.core.service.RefreshTokenCleanupTask refreshTokenCleanupTask(JwtTokenService jwtTokenService) {
        return new com.bss.security.core.service.RefreshTokenCleanupTask(jwtTokenService);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new TestUserDetailsService();
    }

    public static class TestUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            if ("userTest".equals(username)) {
                return new BssSecurityUserAdapter(new SecurityUser() {
                    @Override public String getUsername() { return "userTest"; }
                    @Override public String getPassword() { return "{noop}password"; }
                    @Override public List<String> getRoles() { return Collections.singletonList("ROLE_USER"); }
                    @Override public boolean isEnabled() { return true; }
                });
            } else if ("adminTest".equals(username)) {
                return new BssSecurityUserAdapter(new SecurityUser() {
                    @Override public String getUsername() { return "adminTest"; }
                    @Override public String getPassword() { return "{noop}password"; }
                    @Override public List<String> getRoles() { return Collections.singletonList("ROLE_BSS_ADMIN"); }
                    @Override public boolean isEnabled() { return true; }
                });
            }
            throw new UsernameNotFoundException("User not found");
        }
    }
}

@RestController
class TestController {
    @GetMapping("/api/test")
    public String test() {
        return "Allowed!";
    }
}
