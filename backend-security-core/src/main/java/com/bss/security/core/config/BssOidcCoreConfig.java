package com.bss.security.core.config;

import com.bss.security.core.identity.BssOidcSupport;
import com.bss.security.core.oidc.OidcIdentitySupport;
import com.bss.security.core.oidc.OidcJwkSetProvider;
import com.bss.security.core.oidc.OidcProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Cableado del núcleo OIDC genérico (FEAT-0014).
 *
 * <p>Publica el bean {@link BssOidcSupport} que el selector de identidad (FEAT-0013) detecta
 * para habilitar el modo {@code oidc}. El bean existe sólo cuando la aplicación declaró una
 * allowlist de issuers: sin esa configuración el starter debe seguir comportándose como
 * {@code local} y no puede publicar un soporte OIDC vacío (eso volvería ambigua la identidad,
 * BR-003 de FEAT-0013).
 *
 * <p>La resolución de claves llega como {@link OidcJwkSetProvider} inyectado (módulo de JWKS,
 * FEAT-0007). Si no hay provider, el bean se publica igual y
 * {@link OidcIdentitySupport#validateConfiguration()} aborta el arranque con un mensaje
 * accionable cuando el modo es {@code oidc} (C-07), en vez de romper en el primer token.
 */
@Configuration
@EnableConfigurationProperties(OidcProperties.class)
public class BssOidcCoreConfig {

    /**
     * Soporte OIDC del core, disponible cuando hay issuers configurados.
     *
     * @param properties      allowlist de issuers enlazada desde {@code bss.security.oidc.*}
     * @param jwkSetProviders resolvedor de claves; lo aporta FEAT-0007
     */
    @Bean
    @ConditionalOnMissingBean(BssOidcSupport.class)
    @Conditional(OidcIssuersConfiguredCondition.class)
    public BssOidcSupport bssOidcSupport(OidcProperties properties,
                                         ObjectProvider<OidcJwkSetProvider> jwkSetProviders) {
        return new OidcIdentitySupport(properties, jwkSetProviders.getIfAvailable());
    }

    /**
     * Matchea cuando el entorno declara al menos una entrada de
     * {@code bss.security.oidc.issuers[*]}.
     *
     * <p>Se inspeccionan los nombres de propiedad en vez de usar
     * {@code @ConditionalOnProperty} con un índice fijo porque una entrada inválida puede no
     * tener {@code issuer} (justamente el caso que BR-007 quiere hacer fallar al arrancar) y
     * el bean tiene que existir para que {@code validateConfiguration()} reporte el problema.
     */
    static final class OidcIssuersConfiguredCondition extends SpringBootCondition {

        private static final String ISSUERS_PREFIX = "bss.security.oidc.issuers[";

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Environment environment = context.getEnvironment();
            if (environment instanceof ConfigurableEnvironment configurableEnvironment) {
                for (PropertySource<?> propertySource : configurableEnvironment.getPropertySources()) {
                    if (propertySource instanceof EnumerablePropertySource<?> enumerable) {
                        for (String name : enumerable.getPropertyNames()) {
                            if (name.startsWith(ISSUERS_PREFIX)) {
                                return ConditionOutcome.match("bss.security.oidc.issuers configurado");
                            }
                        }
                    }
                }
            }
            return ConditionOutcome.noMatch("bss.security.oidc.issuers no configurado");
        }
    }
}
