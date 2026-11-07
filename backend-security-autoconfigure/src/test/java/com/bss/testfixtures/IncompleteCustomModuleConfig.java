package com.bss.testfixtures;

import com.bss.security.core.exception.BssConfigurationException;
import com.bss.security.core.identity.BssOidcSupport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

/**
 * Simula un proveedor {@code custom} declarado sin su configuración mínima (FEAT-0013 · AF-05):
 * publica el soporte pero falla al validarlo, para probar el fail-fast del arranque.
 */
@Configuration
public class IncompleteCustomModuleConfig {

    @Bean
    public BssOidcSupport customSupport() {
        return new BssOidcSupport() {
            @Override
            public String provider() {
                return "custom";
            }

            @Override
            public Authentication authenticate(String bearerToken) {
                throw new BadCredentialsException("sin uso");
            }

            @Override
            public void validateConfiguration() {
                throw new BssConfigurationException(
                        "provider custom requiere declarar issuers, audiences y algorithms antes de arrancar.");
            }
        };
    }
}
