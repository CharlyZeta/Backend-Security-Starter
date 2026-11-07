package com.bss.testfixtures.oidc;

import com.bss.testfixtures.TestOidcSupport;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Aplicación de prueba en modo {@code oidc}. Vive en su propio paquete para que el
 * component scan no la mezcle con {@code AutoConfigOnlyApp}.
 */
@SpringBootApplication
public class OidcTestApp {

    public static void main(String[] args) {
        SpringApplication.run(OidcTestApp.class, args);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            if ("userTest".equals(username)) {
                return User.withUsername("userTest").password("{noop}pw").roles("USER").build();
            }
            throw new UsernameNotFoundException("User not found: " + username);
        };
    }

    @Bean
    public TestOidcSupport testOidcSupport() {
        return new TestOidcSupport();
    }

    @RestController
    static class OidcTestController {
        @GetMapping("/api/test")
        public String test() {
            return "Allowed!";
        }
    }
}
