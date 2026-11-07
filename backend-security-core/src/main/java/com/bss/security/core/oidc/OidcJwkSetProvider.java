package com.bss.security.core.oidc;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Seam de resolución de claves del núcleo OIDC (FEAT-0014 · AS-02).
 *
 * <p>Este contrato <strong>no</strong> resuelve claves: sólo define el punto donde el módulo
 * de resolución y caché de JWKS (FEAT-0007) se enchufa. El núcleo OIDC pide el {@link JWKSet}
 * del issuer y Nimbus selecciona la clave por {@code kid} dentro de ese set
 * (BR-004: el {@code kid} nunca elige issuer ni algoritmo).
 *
 * <p>La implementación puede ir a red (o a una caché) y decidir cuándo refrescar. El núcleo
 * no asume nada sobre el origen: para tests alcanza con devolver un {@code JWKSet} estático
 * en memoria (C-06).
 */
@FunctionalInterface
public interface OidcJwkSetProvider {

    /**
     * Devuelve el JWKS vigente del issuer.
     *
     * @param issuer entrada de la allowlist para la que se piden claves
     * @return JWKS del issuer; nunca {@code null}
     */
    JWKSet jwkSetFor(OidcIssuer issuer);
}
