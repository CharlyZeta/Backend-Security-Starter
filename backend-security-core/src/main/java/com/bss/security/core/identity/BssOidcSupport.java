package com.bss.security.core.identity;

import org.springframework.security.core.Authentication;

/**
 * Seam entre el selector de modo de identidad (FEAT-0013) y el núcleo OIDC (FEAT-0014).
 *
 * <p>El módulo OIDC publica un bean de este tipo; su sola presencia habilita el modo
 * {@code oidc}. Si no hay ningún bean, el modo {@code oidc} no está disponible y el
 * arranque falla con un mensaje accionable (BR-004).
 *
 * <p>Contrato del implementador: {@link #authenticate(String)} devuelve la
 * {@link Authentication} del token o lanza {@link org.springframework.security.core.AuthenticationException}
 * si el token no es válido. Nunca debe devolver {@code null}.
 */
public interface BssOidcSupport {

    /** Nombre del proveedor que declara este soporte (por ejemplo {@code entra}). */
    String provider();

    /**
     * Valida la configuración del soporte al arrancar (issuers, audiences, algoritmos, claves).
     * El selector lo invoca cuando el modo es {@code oidc}: un proveedor incompleto debe abortar
     * el arranque con un mensaje accionable, no fallar en el primer token (AF-05).
     *
     * @throws RuntimeException si la configuración está incompleta o es incoherente
     */
    default void validateConfiguration() {
        // El núcleo OIDC (FEAT-0014) implementa esta validación.
    }

    /**
     * Valida el bearer token y devuelve la autenticación resultante.
     *
     * @param bearerToken token sin el prefijo {@code Bearer }
     * @return autenticación no nula
     * @throws org.springframework.security.core.AuthenticationException si el token no es válido
     */
    Authentication authenticate(String bearerToken);
}
