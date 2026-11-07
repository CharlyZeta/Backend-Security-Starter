package com.bss.security.core.oidc;

import com.bss.security.core.exception.BssConfigurationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.bss.security.core.oidc.OidcTestFixtures.AUDIENCE;
import static com.bss.security.core.oidc.OidcTestFixtures.EC256_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.EC384_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.JWKS_URI;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_EC256;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_EC384;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_RSA;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_RSA_BACKUP;
import static com.bss.security.core.oidc.OidcTestFixtures.OTHER_ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.RSA_BACKUP_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.RSA_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.assertRejected;
import static com.bss.security.core.oidc.OidcTestFixtures.claims;
import static com.bss.security.core.oidc.OidcTestFixtures.claimsWithoutAudience;
import static com.bss.security.core.oidc.OidcTestFixtures.countingProvider;
import static com.bss.security.core.oidc.OidcTestFixtures.decoder;
import static com.bss.security.core.oidc.OidcTestFixtures.issuer;
import static com.bss.security.core.oidc.OidcTestFixtures.properties;
import static com.bss.security.core.oidc.OidcTestFixtures.rsaIssuer;
import static com.bss.security.core.oidc.OidcTestFixtures.standardJwkSet;
import static com.bss.security.core.oidc.OidcTestFixtures.token;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FEAT-0014 — Business Rules (BR-001..BR-007).
 *
 * <p>Cada BR se verifica contra el decoder compuesto (allowlist) y, cuando la regla es de
 * configuración, contra {@link OidcIdentitySupport#validateConfiguration()}.
 */
class OidcBusinessRulesTest {

    // ------------------------------------------------------------------ BR-001

    @Test
    @DisplayName("BR-001: GIVEN una allowlist cerrada WHEN llega un token con iss no declarado THEN se rechaza sin descubrimiento implícito")
    void testBR001_issuerAllowlistIsClosedAndNoImplicitDiscoveryHappens() throws Exception {
        CountingJwkSetProvider provider = countingProvider(standardJwkSet());
        OidcJwtDecoder decoder = decoder(provider, rsaIssuer());
        // Firma válida con una clave del issuer declarado, pero el `iss` es otro: no debe "probar" el issuer conocido.
        JWTClaimsSet claims = claims(OTHER_ISSUER, AUDIENCE).build();
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, claims);

        assertThatThrownBy(() -> decoder.decode(token))
                .as("el iss no declarado no se resuelve por descubrimiento")
                .isInstanceOf(AuthenticationException.class);
        assertThat(provider.calls())
                .as("sin issuer en la allowlist no hay resolución de claves")
                .isZero();
    }

    // ------------------------------------------------------------------ BR-002

    @Test
    @DisplayName("BR-002: GIVEN un issuer con algoritmos permitidos WHEN el alg del token no pertenece al conjunto THEN se rechaza")
    void testBR002_algMustBelongToIssuerAlgorithmSet() throws Exception {
        OidcJwtDecoder decoder = decoder(
                issuer(ISSUER, List.of("RS256", "RS512"), List.of(AUDIENCE), Duration.ofSeconds(60)));
        // RS384 queda fuera del conjunto declarado, aunque la firma sea matemáticamente válida.
        String token = token(JWSAlgorithm.RS384, KID_RSA, RSA_KEY);

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(AuthenticationException.class);
    }

    // ------------------------------------------------------------------ BR-003

    @Test
    @DisplayName("BR-003: GIVEN los seis algoritmos soportados WHEN cada uno se declara y firma THEN se acepta")
    void testBR003_coreSupportsRs256Rs384Rs512Es256Es384AndPs256() throws Exception {
        assertThat(OidcIssuer.SUPPORTED_ALGORITHMS)
                .containsExactlyInAnyOrder("RS256", "RS384", "RS512", "ES256", "ES384", "PS256");

        record Case(JWSAlgorithm algorithm, String kid, KeyPair key) {
        }
        List<Case> cases = List.of(
                new Case(JWSAlgorithm.RS256, KID_RSA, RSA_KEY),
                new Case(JWSAlgorithm.RS384, KID_RSA, RSA_KEY),
                new Case(JWSAlgorithm.RS512, KID_RSA, RSA_KEY),
                new Case(JWSAlgorithm.ES256, KID_EC256, EC256_KEY),
                new Case(JWSAlgorithm.ES384, KID_EC384, EC384_KEY),
                new Case(JWSAlgorithm.PS256, KID_RSA, RSA_KEY));

        for (Case testCase : cases) {
            OidcJwtDecoder decoder = decoder(
                    issuer(ISSUER, List.of(testCase.algorithm().getName()),
                            List.of(AUDIENCE), Duration.ofSeconds(60)));
            String token = token(testCase.algorithm(), testCase.kid(), testCase.key());

            assertThatCode(() -> decoder.decode(token))
                    .as("el núcleo debe soportar %s", testCase.algorithm().getName())
                    .doesNotThrowAnyException();
        }
    }

    // ------------------------------------------------------------------ BR-004

    @Test
    @DisplayName("BR-004: GIVEN dos claves en el JWKS del issuer WHEN el kid selecciona una clave THEN la firma se valida con esa clave (nunca cambia el alg ni el issuer)")
    void testBR004_kidSelectsKeyWithinIssuerNotAlgorithmNorIssuer() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer()); // JWKS con KID_RSA y KID_RSA_BACKUP

        // Positivo: cada kid del mismo issuer selecciona su propia clave.
        assertThatCode(() -> decoder.decode(token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY)))
                .doesNotThrowAnyException();
        assertThatCode(() -> decoder.decode(token(JWSAlgorithm.RS256, KID_RSA_BACKUP, RSA_BACKUP_KEY)))
                .doesNotThrowAnyException();

        // Negativo: el kid declara la clave 1 pero la firma viene de la clave 2 → rechazo.
        assertRejected(decoder, token(JWSAlgorithm.RS256, KID_RSA, RSA_BACKUP_KEY));

        // Negativo: un kid de una clave EC no habilita ES256 sobre un issuer que solo permite RS256.
        assertRejected(decoder, token(JWSAlgorithm.ES256, KID_EC256, EC256_KEY));
    }

    // ------------------------------------------------------------------ BR-005

    @Test
    @DisplayName("BR-005: GIVEN un issuer con audiences declaradas WHEN el token no trae aud permitida THEN se rechaza")
    void testBR005_tokenWithoutAllowedAudienceIsRejected() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, claimsWithoutAudience(ISSUER));

        assertThatThrownBy(() -> decoder.decode(token))
                .as("un token sin claim aud no puede satisfacer la allowlist de audiences")
                .isInstanceOf(JwtException.class);
    }

    // ------------------------------------------------------------------ BR-006

    @Test
    @DisplayName("BR-006: GIVEN skew configurado por issuer WHEN el token cae dentro/fuera del skew THEN se acepta/rechaza, y el default es 60 s con máximo 300 s")
    void testBR006_clockSkewIsConfigurablePerIssuerWithDefaultAndMax() throws Exception {
        // Default y máximo declarados por el contrato.
        OidcIssuer defaultSkew = new OidcIssuer(
                ISSUER, List.of("RS256"), List.of(AUDIENCE), null, JWKS_URI);
        assertThat(defaultSkew.clockSkew()).isEqualTo(Duration.ofSeconds(60));
        assertThat(OidcIssuer.MAX_CLOCK_SKEW).isEqualTo(Duration.ofSeconds(300));

        // Fuera de rango: > 300 s no es configurable, aborta la validación.
        OidcIssuer outOfRange = issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), Duration.ofSeconds(400));
        OidcIdentitySupport invalid = new OidcIdentitySupport(
                properties(outOfRange), countingProvider(standardJwkSet()));
        assertThatThrownBy(invalid::validateConfiguration)
                .isInstanceOf(BssConfigurationException.class);

        Instant now = Instant.now();
        JWTClaimsSet expiredClaims = claims(ISSUER, AUDIENCE)
                .issueTime(Date.from(now.minusSeconds(600)))
                .expirationTime(Date.from(now.minusSeconds(30)))
                .build();
        String expiredToken = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, expiredClaims);

        // Con skew 60 s un token vencido hace 30 s todavía es aceptable.
        OidcJwtDecoder lenient = decoder(
                issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), Duration.ofSeconds(60)));
        assertThatCode(() -> lenient.decode(expiredToken)).doesNotThrowAnyException();

        // Con skew 0 el mismo token está vencido y se rechaza.
        OidcJwtDecoder strict = decoder(
                issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), Duration.ZERO));
        assertRejected(strict, expiredToken);
    }

    // ------------------------------------------------------------------ BR-007

    @Test
    @DisplayName("BR-007: GIVEN una entrada sin algoritmo, sin audience o con iss vacío WHEN se valida la configuración THEN el arranque falla nombrando la entrada")
    void testBR007_incompleteEntryBlocksStartup() {
        OidcJwkSetProvider provider = countingProvider(standardJwkSet());
        List<OidcIssuer> incompleteEntries = List.of(
                new OidcIssuer(ISSUER, List.of(), List.of(AUDIENCE), Duration.ofSeconds(60), JWKS_URI),
                new OidcIssuer(ISSUER, List.of("RS256"), List.of(), Duration.ofSeconds(60), JWKS_URI),
                new OidcIssuer("", List.of("RS256"), List.of(AUDIENCE), Duration.ofSeconds(60), JWKS_URI));

        for (OidcIssuer entry : incompleteEntries) {
            OidcIdentitySupport support = new OidcIdentitySupport(properties(entry), provider);
            assertThatThrownBy(support::validateConfiguration)
                    .as("entrada incompleta: issuer=%s alg=%s aud=%s",
                            entry.issuer(), entry.algorithms(), entry.audiences())
                    .isInstanceOf(BssConfigurationException.class)
                    .hasMessageContaining("issuers[0]");
        }
    }
}
