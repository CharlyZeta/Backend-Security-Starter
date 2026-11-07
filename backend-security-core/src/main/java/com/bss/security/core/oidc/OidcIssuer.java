package com.bss.security.core.oidc;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Entrada de la allowlist de issuers OIDC (FEAT-0014 · BR-001..BR-007).
 *
 * <p>La allowlist es cerrada: cada entrada declara el {@code iss} exacto que acepta, el
 * conjunto de algoritmos de firma permitidos para ese emisor, las audiencias válidas, el
 * skew de reloj tolerado y la URI del JWKS del issuer.
 *
 * <p>Invariantes de construcción:
 * <ul>
 *   <li>{@code algorithms} y {@code audiences} nunca son {@code null} (lista vacía si el
 *       llamador pasa {@code null}); una lista vacía es configuración inválida y la detecta
 *       {@link OidcIdentitySupport#validateConfiguration()}.</li>
 *   <li>{@code clockSkew} {@code null} adopta el default documentado de 60 s (BR-006).</li>
 *   <li>No se valida acá: la validación completa vive en
 *       {@link OidcIdentitySupport#validateConfiguration()} para poder reportar la entrada
 *       incompleta con su índice y campo (C-07).</li>
 * </ul>
 *
 * @param issuer      valor exacto del claim {@code iss} aceptado
 * @param algorithms  algoritmos de firma permitidos para este issuer
 * @param audiences   audiencias permitidas para este issuer
 * @param clockSkew   tolerancia de reloj para {@code exp}/{@code nbf} (default 60 s, máximo 300 s)
 * @param jwksUri     URI absoluta del JWKS del issuer (la resolución es de FEAT-0007)
 */
public record OidcIssuer(
        String issuer,
        List<String> algorithms,
        List<String> audiences,
        Duration clockSkew,
        String jwksUri
) {

    /** Default de {@code clock-skew} cuando la configuración no declara uno (BR-006). */
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

    /** Tope de {@code clock-skew} admitido (BR-006). */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(300);

    /**
     * Algoritmos soportados en el núcleo (BR-003). No incluye {@code none} ni la familia
     * {@code HS*} a propósito: un token de un IdP externo nunca se valida con MAC simétrico.
     */
    public static final Set<String> SUPPORTED_ALGORITHMS =
            Set.of("RS256", "RS384", "RS512", "ES256", "ES384", "PS256");

    public OidcIssuer {
        issuer = issuer == null ? null : issuer.trim();
        // Los algoritmos se normalizan a mayúsculas: la configuración tolera "rs256" y la
        // comparación en runtime (header JWS, siempre mayúsculas) no se desalinea.
        algorithms = copyOf(algorithms).stream()
                .map(algorithm -> algorithm == null ? null : algorithm.trim().toUpperCase(java.util.Locale.ROOT))
                .toList();
        audiences = copyOf(audiences);
        clockSkew = clockSkew == null ? DEFAULT_CLOCK_SKEW : clockSkew;
        jwksUri = jwksUri == null ? null : jwksUri.trim();
    }

    /**
     * Copia defensiva que preserva {@code null}s dentro de la lista (se rechazan en la
     * validación con un mensaje accionable, en vez de romper el constructor).
     */
    private static List<String> copyOf(List<String> values) {
        if (values == null) {
            return List.of();
        }
        return Collections.unmodifiableList(new ArrayList<>(values));
    }
}
