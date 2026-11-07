package com.bss.security.core.oidc;

import com.bss.security.core.exception.BssConfigurationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Duration;
import java.util.List;

import static com.bss.security.core.oidc.OidcTestFixtures.AUDIENCE;
import static com.bss.security.core.oidc.OidcTestFixtures.EC256_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_EC256;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_RSA;
import static com.bss.security.core.oidc.OidcTestFixtures.OTHER_AUDIENCE;
import static com.bss.security.core.oidc.OidcTestFixtures.OTHER_ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.RSA_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.claims;
import static com.bss.security.core.oidc.OidcTestFixtures.countingProvider;
import static com.bss.security.core.oidc.OidcTestFixtures.decoder;
import static com.bss.security.core.oidc.OidcTestFixtures.es256Issuer;
import static com.bss.security.core.oidc.OidcTestFixtures.hs256TokenSignedWithRsaPublicKey;
import static com.bss.security.core.oidc.OidcTestFixtures.issuer;
import static com.bss.security.core.oidc.OidcTestFixtures.noneToken;
import static com.bss.security.core.oidc.OidcTestFixtures.properties;
import static com.bss.security.core.oidc.OidcTestFixtures.rsaIssuer;
import static com.bss.security.core.oidc.OidcTestFixtures.standardJwkSet;
import static com.bss.security.core.oidc.OidcTestFixtures.token;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FEAT-0014 — Acceptance Criteria (AC-001..AC-008).
 *
 * <p>Los AC describen el resultado observable (token aceptado o rechazado). Acá se verifica en
 * la unidad que implementa la decisión: el decoder compuesto {@link OidcJwtDecoder} para
 * aceptación/rechazo de tokens y {@link OidcIdentitySupport#validateConfiguration()} para el
 * fail-fast de configuración. Los tests no hacen red: el {@code OidcJwkSetProvider} devuelve un
 * {@link com.nimbusds.jose.jwk.JWKSet} estático generado en memoria.
 */
class OidcAcceptanceCriteriaTest {

    // ------------------------------------------------------------------ AC-001

    @Test
    @DisplayName("AC-001: GIVEN un issuer declarado y un token RS256 válido con aud permitida WHEN se valida THEN se acepta")
    void testAC001_rs256ValidTokenWithAllowedAudienceIsAccepted() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY);

        Jwt jwt = decoder.decode(token);

        assertThat(jwt.getClaimAsString("iss")).isEqualTo(ISSUER);
        assertThat(jwt.getSubject()).isEqualTo("userTest");
        assertThat(jwt.getAudience()).containsExactly(AUDIENCE);
    }

    // ------------------------------------------------------------------ AC-002

    @Test
    @DisplayName("AC-002: GIVEN un issuer declarado con ES256 permitido WHEN llega un token ES256 válido THEN se acepta")
    void testAC002_es256ValidTokenIsAccepted() throws Exception {
        OidcJwtDecoder decoder = decoder(es256Issuer());
        String token = token(JWSAlgorithm.ES256, KID_EC256, EC256_KEY);

        Jwt jwt = decoder.decode(token);

        assertThat(jwt.getClaimAsString("iss")).isEqualTo(ISSUER);
        assertThat(jwt.getHeaders()).containsEntry("alg", "ES256");
    }

    // ------------------------------------------------------------------ AC-003

    @Test
    @DisplayName("AC-003: GIVEN un token cuyo alg no está en la lista del issuer WHEN se valida THEN se rechaza")
    void testAC003_algNotInIssuerAllowlistIsRejected() throws Exception {
        // El issuer solo admite RS256; el token está bien firmado con la misma clave pero usa RS384.
        OidcIssuer issuer = issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), Duration.ofSeconds(60));
        OidcJwtDecoder decoder = decoder(issuer);
        String token = token(JWSAlgorithm.RS384, KID_RSA, RSA_KEY);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("RS384 no está en la allowlist del issuer")
                .isInstanceOf(AuthenticationException.class);
    }

    // ------------------------------------------------------------------ AC-004

    @Test
    @DisplayName("AC-004: GIVEN un token con iss no declarado WHEN se valida THEN se rechaza y no se consulta ninguna clave")
    void testAC004_unknownIssuerIsRejectedWithoutResolvingKeys() throws Exception {
        CountingJwkSetProvider provider = countingProvider(standardJwkSet());
        OidcJwtDecoder decoder = decoder(provider, rsaIssuer());
        JWTClaimsSet claims = claims(OTHER_ISSUER, AUDIENCE).build();
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, claims);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("el issuer no declarado no está en la allowlist")
                .isInstanceOf(AuthenticationException.class);

        assertThat(provider.calls())
                .as("el issuer se resuelve ANTES de resolver claves (Main Flow paso 2)")
                .isZero();
        assertThat(provider.requestedIssuers()).isEmpty();
    }

    // ------------------------------------------------------------------ AC-005

    @Test
    @DisplayName("AC-005: GIVEN un token con aud fuera de las permitidas WHEN se valida THEN se rechaza")
    void testAC005_audienceOutsideAllowlistIsRejected() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        JWTClaimsSet claims = claims(ISSUER, OTHER_AUDIENCE).build();
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, claims);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("la audiencia no está permitida para el issuer")
                .isInstanceOf(JwtException.class);
    }

    // ------------------------------------------------------------------ AC-006

    @Test
    @DisplayName("AC-006: GIVEN un token con alg=none WHEN se valida THEN se rechaza")
    void testAC006_algNoneIsRejected() {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        String token = noneToken(ISSUER, AUDIENCE);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("los JWS no firmados (alg=none) nunca son aceptables")
                .isInstanceOf(JwtException.class);
    }

    // ------------------------------------------------------------------ AC-007

    @Test
    @DisplayName("AC-007: GIVEN un token alg=HS256 firmado con la clave pública del issuer WHEN se valida THEN se rechaza")
    void testAC007_hs256SignedWithRsaPublicKeyIsRejected() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        String token = hs256TokenSignedWithRsaPublicKey(RSA_KEY, ISSUER, AUDIENCE);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("HS256 no está en la allowlist: no hay confusión de algoritmos")
                .isInstanceOf(AuthenticationException.class);
    }

    // ------------------------------------------------------------------ AC-008

    @Test
    @DisplayName("AC-008: GIVEN una entrada de allowlist sin algoritmos WHEN arranca/valida la configuración THEN falla indicando la entrada incompleta")
    void testAC008_entryWithoutAlgorithmsFailsConfigurationValidation() {
        OidcIssuer incomplete = new OidcIssuer(
                ISSUER, List.of(), List.of(AUDIENCE), Duration.ofSeconds(60), ISSUER + "/jwks.json");
        OidcIdentitySupport support = new OidcIdentitySupport(
                properties(incomplete), countingProvider(standardJwkSet()));

        assertThatThrownBy(support::validateConfiguration)
                .as("una entrada sin algoritmos debe abortar el arranque (C-07)")
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("issuers[0]");
    }
}
