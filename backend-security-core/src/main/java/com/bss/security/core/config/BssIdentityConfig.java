package com.bss.security.core.config;

import com.bss.security.core.identity.BssIdentityProperties;
import com.bss.security.core.identity.BssIdentitySelector;
import com.bss.security.core.identity.BssOidcSupport;
import com.bss.security.core.identity.OidcAuthenticationFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Beans del modo de identidad (FEAT-0013), en su propia configuración para no crear un ciclo:
 * {@link BssSecurityConfig} consume el selector, así que no puede producirlo.
 */
@Configuration
@EnableConfigurationProperties(BssIdentityProperties.class)
public class BssIdentityConfig {

    /**
     * Selector de modo. La disponibilidad de {@code oidc} se resuelve por la presencia de un
     * {@link BssOidcSupport}, que publica el módulo OIDC del classpath (BR-002).
     */
    @Bean
    public BssIdentitySelector bssIdentitySelector(BssIdentityProperties identityProperties,
                                                   ObjectProvider<BssOidcSupport> supports) {
        return new BssIdentitySelector(identityProperties, supports.orderedStream().toList());
    }

    /** Filtro del modo {@code oidc}. Solo existe cuando el modo declarado es oidc (AC-004). */
    @Bean
    @ConditionalOnProperty(name = "bss.security.mode", havingValue = "oidc")
    public OidcAuthenticationFilter oidcAuthenticationFilter(BssIdentitySelector selector) {
        return new OidcAuthenticationFilter(selector.support());
    }
}
