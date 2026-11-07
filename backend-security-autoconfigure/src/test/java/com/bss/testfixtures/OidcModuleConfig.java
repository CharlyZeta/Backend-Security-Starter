package com.bss.testfixtures;

import com.bss.security.core.identity.BssOidcSupport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Simula el módulo OIDC presente en el classpath: publica un {@link BssOidcSupport}.
 * Se importa explícitamente desde los tests; no es alcanzable por component scan.
 */
@Configuration
public class OidcModuleConfig {

    @Bean
    public BssOidcSupport testOidcSupport() {
        return new TestOidcSupport();
    }
}
