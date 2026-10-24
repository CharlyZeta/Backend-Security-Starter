package com.bss.autoconfigtest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Aplicación mínima SIN component scan de {@code com.bss.security}.
 *
 * Su único propósito es probar que la autoconfiguración del starter registra por sí
 * sola el advice de errores y los handlers (AC-008 / BR-003 de FIX-0001). Si el
 * registro dependiera del scan del consumidor, estos tests fallarían.
 */
@SpringBootApplication
public class AutoConfigOnlyApp {

    public static void main(String[] args) {
        SpringApplication.run(AutoConfigOnlyApp.class, args);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            if ("userTest".equals(username)) {
                return User.withUsername("userTest").password("{noop}pw").roles("USER").build();
            }
            if ("adminTest".equals(username)) {
                return User.withUsername("adminTest").password("{noop}pw").roles("BSS_ADMIN").build();
            }
            throw new UsernameNotFoundException("User not found: " + username);
        };
    }
}
