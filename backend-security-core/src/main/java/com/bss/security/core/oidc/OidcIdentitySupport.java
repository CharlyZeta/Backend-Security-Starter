package com.bss.security.core.oidc;

import com.bss.security.core.exception.BssConfigurationException;
import com.bss.security.core.identity.BssIdentityUnavailableException;
import com.bss.security.core.identity.BssOidcSupport;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Implementación del seam {@link BssOidcSupport} para el núcleo OIDC genérico
 * (FEAT-0014). Publica la allowlist de issuers como un único decoder compuesto
 * ({@link OidcJwtDecoder}) y valida la configuración al arrancar (C-07).
 *
 * <p>Qué hace y qué NO hace:
 * <ul>
 *   <li>Valida firma, {@code iss}, {@code aud}, ventana y algoritmo por issuer.</li>
 *   <li><strong>No</strong> mapea claims a authorities: eso es FEAT-0008. Acá la
 *       {@link Authentication} resultante lleva las authorities vacías, y el principal es
 *       el claim {@code sub} cuando es un string.</li>
 *   <li>La validación del token se delega en Nimbus a través de Spring Security; no hay
 *       criptografía propia (C-02).</li>
 * </ul>
 */
public class OidcIdentitySupport implements BssOidcSupport {

    private final OidcProperties properties;
    private final OidcJwkSetProvider jwkSetProvider;
    private final OidcJwtDecoder decoder;

    /**
     * @param properties      configuración del núcleo OIDC
     * @param jwkSetProvider  resolvedor de claves; en producción lo aporta FEAT-0007.
     *                        Puede ser {@code null} al cablear el contexto sin ese módulo:
     *                        {@link #validateConfiguration()} lo reporta como configuración
     *                        incompleta (C-07) en lugar de fallar en el primer token.
     */
    public OidcIdentitySupport(OidcProperties properties, OidcJwkSetProvider jwkSetProvider) {
        this(properties, jwkSetProvider, new OidcJwtDecoderFactory());
    }

    /**
     * @param properties      configuración del núcleo OIDC
     * @param jwkSetProvider  resolvedor de claves; en producción lo aporta FEAT-0007
     * @param decoderFactory  fábrica de decoders por issuer
     */
    public OidcIdentitySupport(OidcProperties properties,
                               OidcJwkSetProvider jwkSetProvider,
                               OidcJwtDecoderFactory decoderFactory) {
        this.properties = Objects.requireNonNull(properties, "properties cannot be null");
        Objects.requireNonNull(decoderFactory, "decoderFactory cannot be null");
        this.jwkSetProvider = jwkSetProvider;
        this.decoder = jwkSetProvider == null
                ? null
                : new OidcJwtDecoder(properties.getIssuers(), decoderFactory, jwkSetProvider);
    }

    @Override
    public String provider() {
        return this.properties.provider();
    }

    /**
     * Valida la allowlist completa al arrancar (BR-007, AC-008, C-07): una entrada
     * incompleta o insegura aborta el contexto con un mensaje que nombra el índice y el
     * campo, en vez de fallar con el primer token.
     */
    @Override
    public void validateConfiguration() {
        if (this.jwkSetProvider == null) {
            throw new BssConfigurationException(
                    "bss.security.oidc.issuers está configurado pero no hay resolución de claves OIDC "
                            + "(falta un bean OidcJwkSetProvider, que aporta el módulo de JWKS, FEAT-0007).");
        }

        List<OidcIssuer> issuers = this.properties.getIssuers();
        if (issuers == null || issuers.isEmpty()) {
            throw new BssConfigurationException(
                    "bss.security.oidc.issuers está vacío: el modo oidc exige declarar al menos un issuer "
                            + "con issuer, algorithms, audiences, clock-skew y jwks-uri.");
        }

        Set<String> seenIssuers = new HashSet<>();
        for (int index = 0; index < issuers.size(); index++) {
            validateIssuer(index, issuers.get(index), seenIssuers);
        }
    }

    /**
     * Valida el bearer token y devuelve la autenticación.
     *
     * <p>Nunca devuelve {@code null} y nunca propaga una excepción no controlada: todo token
     * inválido (malformado, issuer/alg no permitidos, firma, {@code aud} o ventana) termina
     * en {@link BadCredentialsException}, de modo que el filtro responda 401 y no 500
     * (AF-01..AF-04, C-05).
     */
    @Override
    public Authentication authenticate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new BadCredentialsException("Token OIDC ausente");
        }
        OidcJwtDecoder oidcDecoder = this.decoder;
        if (oidcDecoder == null) {
            // Sólo alcanzable si no se llamó validateConfiguration() antes: misconfiguración.
            throw new AuthenticationServiceException("No hay resolución de claves OIDC configurada");
        }
        try {
            Jwt jwt = oidcDecoder.decode(bearerToken);
            return new UsernamePasswordAuthenticationToken(principal(jwt), null, List.of());
        } catch (BssIdentityUnavailableException unavailable) {
            // FEAT-0007/BR-004: el IdP no está disponible. No es un token inválido: el filtro
            // lo traduce a 503 en lugar de mentir con un 401.
            throw unavailable;
        } catch (RuntimeException ex) {
            // C-04: mensaje genérico; el detalle queda como causa para diagnóstico local.
            throw new BadCredentialsException("Token OIDC inválido", ex);
        }
    }

    private static Object principal(Jwt jwt) {
        String subject = jwt.getSubject();
        // FEAT-0008 mapea claims; acá el principal es el `sub` o, si falta, el token validado.
        return subject == null ? jwt : subject;
    }

    private static void validateIssuer(int index, OidcIssuer issuer, Set<String> seenIssuers) {
        String path = "bss.security.oidc.issuers[" + index + "]";

        if (issuer == null) {
            throw new BssConfigurationException(
                    path + " es nulo: cada entrada de la allowlist debe declarar issuer, algorithms, "
                            + "audiences, clock-skew y jwks-uri.");
        }

        String issuerName = issuer.issuer();
        if (issuerName == null || issuerName.isBlank()) {
            throw new BssConfigurationException(
                    path + ".issuer es obligatorio: una entrada sin `iss` no identifica ningún proveedor.");
        }
        if (!seenIssuers.add(issuerName)) {
            throw new BssConfigurationException(
                    path + ".issuer duplicado: '" + issuerName + "' ya está declarado en la allowlist. "
                            + "Un issuer debe tener una sola entrada para que algoritmo y audiencias no sean ambiguos.");
        }

        validateAlgorithms(path, issuer.algorithms());
        validateAudiences(path, issuer.audiences());
        validateClockSkew(path, issuer.clockSkew());
        validateJwksUri(path, issuer.jwksUri());
    }

    private static void validateAlgorithms(String path, List<String> algorithms) {
        if (algorithms == null || algorithms.isEmpty()) {
            throw new BssConfigurationException(
                    path + ".algorithms está vacío: declarí al menos uno de "
                            + String.join(", ", OidcIssuer.SUPPORTED_ALGORITHMS) + ".");
        }
        for (String algorithm : algorithms) {
            if (algorithm == null || algorithm.isBlank()) {
                throw new BssConfigurationException(
                        path + ".algorithms contiene un valor vacío: declarí uno de "
                                + String.join(", ", OidcIssuer.SUPPORTED_ALGORITHMS) + ".");
            }
            String normalized = algorithm.trim().toUpperCase(Locale.ROOT);
            if (!OidcIssuer.SUPPORTED_ALGORITHMS.contains(normalized)) {
                throw new BssConfigurationException(
                        path + ".algorithms contiene un algoritmo no soportado: '" + algorithm
                                + "'. Soportados: " + String.join(", ", OidcIssuer.SUPPORTED_ALGORITHMS) + ".");
            }
        }
    }

    private static void validateAudiences(String path, List<String> audiences) {
        if (audiences == null || audiences.isEmpty()) {
            throw new BssConfigurationException(
                    path + ".audiences está vacío: un token sin audiencia permitida debe rechazarse "
                            + "(BR-005), así que la entrada necesita al menos una audiencia.");
        }
        for (String audience : audiences) {
            if (audience == null || audience.isBlank()) {
                throw new BssConfigurationException(path + ".audiences contiene un valor vacío.");
            }
        }
    }

    private static void validateClockSkew(String path, Duration clockSkew) {
        if (clockSkew == null) {
            throw new BssConfigurationException(
                    path + ".clock-skew no puede ser nulo (default " + OidcIssuer.DEFAULT_CLOCK_SKEW.toSeconds() + "s).");
        }
        if (clockSkew.isNegative()) {
            throw new BssConfigurationException(path + ".clock-skew no puede ser negativo.");
        }
        if (clockSkew.compareTo(OidcIssuer.MAX_CLOCK_SKEW) > 0) {
            throw new BssConfigurationException(
                    path + ".clock-skew=" + clockSkew.toSeconds() + "s excede el máximo de "
                            + OidcIssuer.MAX_CLOCK_SKEW.toSeconds() + "s (BR-006).");
        }
    }

    private static void validateJwksUri(String path, String jwksUri) {
        if (jwksUri == null || jwksUri.isBlank()) {
            throw new BssConfigurationException(
                    path + ".jwks-uri es obligatorio: sin URI de JWKS no se puede verificar la firma.");
        }
        URI uri;
        try {
            uri = URI.create(jwksUri);
        } catch (IllegalArgumentException ex) {
            throw new BssConfigurationException(
                    path + ".jwks-uri no es una URI válida: '" + jwksUri + "'.");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        // FEAT-0007/BR-005: el JWKS se descarga sólo por HTTPS. Aceptar http:// permitiría
        // sustituir el conjunto de claves por MITM y forjar tokens válidos para el issuer.
        if (!uri.isAbsolute() || uri.getHost() == null || !"https".equals(scheme)) {
            throw new BssConfigurationException(
                    path + ".jwks-uri debe ser una URL absoluta https (el JWKS no se descarga por http): '"
                            + jwksUri + "'.");
        }
    }
}
