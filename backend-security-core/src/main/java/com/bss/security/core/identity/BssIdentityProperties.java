package com.bss.security.core.identity;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades del modo de identidad (FEAT-0013).
 *
 * <pre>
 * bss:
 *   security:
 *     mode: local | oidc        # ausente = no declarado (se valida al arrancar)
 *     oidc:
 *       provider: entra         # obligatorio en modo oidc
 * </pre>
 *
 * <p>{@code mode} se deja sin default a propósito: distinguir "no declarado" de
 * "declarado como local" es lo que permite fallar cuando el módulo OIDC está presente
 * y la identidad es ambigua (BR-003).
 */
@ConfigurationProperties(prefix = "bss.security")
public class BssIdentityProperties {

    private String mode;
    private final Oidc oidc = new Oidc();

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public Oidc getOidc() {
        return oidc;
    }

    public static class Oidc {

        private String provider;

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }
    }
}
