package com.bss.security.core.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Construye el {@link JwtDecoder} de un issuer de la allowlist (FEAT-0014 · Main Flow paso 3).
 *
 * <p>Garantías del decoder construido:
 * <ul>
 *   <li><strong>Algoritmo fijado por issuer</strong>: el {@code JWSVerificationKeySelector} sólo
 *       admite los algoritmos declarados en la entrada; el header del token no amplía esa lista
 *       (BR-002, AC-006, AC-007).</li>
 *   <li><strong>{@code iss} validado contra la entrada</strong>: {@link JwtIssuerValidator}.</li>
 *   <li><strong>{@code aud} validada contra las audiencias de la entrada</strong>: validador
 *       propio; un token sin audiencia permitida se rechaza (BR-005, AF-03).</li>
 *   <li><strong>Ventana {@code exp}/{@code nbf} con el skew de la entrada</strong> (BR-006):
 *       {@link JwtTimestampValidator} y, además, el claims verifier de Nimbus con el mismo
 *       {@code maxClockSkew} para que no quede un 60 s implícito de Nimbus pisando el valor
 *       configurado.</li>
 *   <li><strong>Claves sólo del provider inyectado</strong>: la {@link JWKSource} delega en
 *       {@link OidcJwkSetProvider#jwkSetFor(OidcIssuer)}; no hay descarga ni criptografía
 *       propia (C-02, AS-02). El {@code kid} selecciona la clave dentro de ese JWKS, nunca el
 *       issuer ni el algoritmo (BR-004).</li>
 * </ul>
 *
 * <p>La caché de claves y el refresco son responsabilidad de FEAT-0007: acá se pide el
 * {@code JWKSet} en cada verificación para que esa caché sea la que decida el refresco.
 */
public class OidcJwtDecoderFactory {

    /**
     * Construye el decoder del issuer.
     *
     * @param issuer   entrada validada de la allowlist
     * @param provider resolvedor de claves del issuer (nunca {@code null})
     * @return decoder que valida firma, {@code iss}, {@code aud} y ventana con el skew del issuer
     */
    public JwtDecoder decoderFor(OidcIssuer issuer, OidcJwkSetProvider provider) {
        Objects.requireNonNull(issuer, "issuer cannot be null");
        Objects.requireNonNull(provider, "provider cannot be null");

        Set<JWSAlgorithm> allowedAlgorithms = toJwsAlgorithms(issuer.algorithms());

        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> {
            JWKSet jwkSet = provider.jwkSetFor(issuer);
            if (jwkSet == null) {
                // Fail-closed: sin JWKS no hay firma verificable.
                throw new KeySourceException("JWKS no disponible para el issuer configurado");
            }
            return jwkSelector.select(jwkSet);
        };

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(allowedAlgorithms, jwkSource));

        // El ctor sin argumentos de Nimbus está deprecado: se usa el explícito equivalente
        // (sin claims exactos ni requeridos) y se fija el skew del issuer.
        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
                new DefaultJWTClaimsVerifier<>(null, null, null, null);
        claimsVerifier.setMaxClockSkew(maxClockSkewSeconds(issuer.clockSkew()));
        processor.setJWTClaimsSetVerifier(claimsVerifier);

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(validatorsFor(issuer));
        return decoder;
    }

    private static Set<JWSAlgorithm> toJwsAlgorithms(List<String> algorithms) {
        Set<JWSAlgorithm> parsed = new LinkedHashSet<>();
        if (algorithms != null) {
            for (String algorithm : algorithms) {
                if (algorithm != null && !algorithm.isBlank()) {
                    parsed.add(JWSAlgorithm.parse(algorithm.trim()));
                }
            }
        }
        return parsed;
    }

    private static int maxClockSkewSeconds(Duration clockSkew) {
        Duration effective = clockSkew == null ? OidcIssuer.DEFAULT_CLOCK_SKEW : clockSkew;
        long seconds = Math.max(0L, effective.getSeconds());
        return (int) Math.min(Integer.MAX_VALUE, seconds);
    }

    private static OAuth2TokenValidator<Jwt> validatorsFor(OidcIssuer issuer) {
        Duration clockSkew = issuer.clockSkew() == null ? OidcIssuer.DEFAULT_CLOCK_SKEW : issuer.clockSkew();
        // Orden: ventana -> issuer -> audiencia -> exp obligatorio. Todos deben pasar.
        return new DelegatingOAuth2TokenValidator<>(List.of(
                new JwtTimestampValidator(clockSkew),
                new JwtIssuerValidator(issuer.issuer()),
                new AudienceValidator(issuer.audiences()),
                RequiredExpiryValidator.INSTANCE
        ));
    }

    /**
     * Exige el claim {@code exp}: un token sin vencimiento vale para siempre y
     * {@link JwtTimestampValidator} lo ignora cuando el claim no está presente (C-05/BR-006).
     */
    private enum RequiredExpiryValidator implements OAuth2TokenValidator<Jwt> {
        INSTANCE;

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            if (token.getExpiresAt() != null) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "El token no declara exp", null));
        }
    }

    /**
     * Valida que el claim {@code aud} del token interseque las audiencias de la entrada.
     * Es defensivo con claims malformados: cualquier valor no convertible en lista de strings
     * se trata como ausencia de audiencia (rechazo), nunca como excepción no controlada (C-05).
     */
    private static final class AudienceValidator implements OAuth2TokenValidator<Jwt> {

        private static final OAuth2Error INVALID_AUDIENCE = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "El token no contiene una audiencia permitida",
                "https://tools.ietf.org/html/rfc6750#section-3.1");

        private final List<String> allowedAudiences;

        private AudienceValidator(List<String> allowedAudiences) {
            this.allowedAudiences = allowedAudiences == null ? List.of() : List.copyOf(allowedAudiences);
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            List<String> tokenAudiences;
            try {
                tokenAudiences = token.getAudience();
            } catch (RuntimeException ex) {
                // C-05: un `aud` con forma inesperada se rechaza, no explota.
                tokenAudiences = null;
            }
            if (this.allowedAudiences.isEmpty() || tokenAudiences == null
                    || Collections.disjoint(tokenAudiences, this.allowedAudiences)) {
                return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
            }
            return OAuth2TokenValidatorResult.success();
        }
    }
}
