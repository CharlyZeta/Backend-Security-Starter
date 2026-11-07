package com.bss.autoconfigure.oidc;

import com.bss.security.core.config.BssOidcCoreConfig;
import com.bss.security.core.identity.BssOidcSupport;
import com.bss.security.core.oidc.OidcIssuer;
import com.bss.security.core.oidc.OidcJwkSetProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FEAT-0014 — Main Flow funcional, cableado desde el contexto de Spring.
 *
 * <p>Verifica el flujo del contrato de punta a punta dentro de la unidad funcional:
 * <ol>
 *   <li>la aplicación declara la allowlist de issuers por propiedades;</li>
 *   <li>el issuer del token se resuelve contra la allowlist <b>antes</b> de pedir claves;</li>
 *   <li>con el issuer identificado se valida firma, {@code aud} y ventana;</li>
 *   <li>si es válido, hay autenticación; si no, se rechaza.</li>
 * </ol>
 *
 * <p>El {@link OidcJwkSetProvider} es un stub en memoria: los tests no hacen red.
 */
class OidcCoreMainFlowTest {

    private static final String ISSUER = "https://idp.test.local";
    private static final String OTHER_ISSUER = "https://otro-idp.test.local";
    private static final String AUDIENCE = "bss-api";
    private static final String KID = "rsa-key-1";

    private static final KeyPair RSA_KEY = generateRsaKeyPair();

    private final StaticJwkSetProvider provider = new StaticJwkSetProvider();

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(BssOidcCoreConfig.class)
            .withBean(OidcJwkSetProvider.class, () -> provider)
            .withPropertyValues(
                    "bss.security.oidc.provider=test",
                    "bss.security.oidc.issuers[0].issuer=" + ISSUER,
                    "bss.security.oidc.issuers[0].algorithms[0]=RS256",
                    "bss.security.oidc.issuers[0].audiences[0]=" + AUDIENCE,
                    "bss.security.oidc.issuers[0].clock-skew=60s",
                    "bss.security.oidc.issuers[0].jwks-uri=" + ISSUER + "/jwks.json");

    @Test
    @DisplayName("Main Flow: GIVEN la allowlist declarada WHEN llega un token de un issuer permitido THEN se identifica el issuer, se valida y se autentica")
    void testMainFlow_allowlistedIssuerTokenIsValidatedAndAuthenticated() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(BssOidcSupport.class);

            BssOidcSupport support = context.getBean(BssOidcSupport.class);
            assertThat(support.provider()).isEqualTo("test");

            // Paso 1: la allowlist configurada es coherente y valida al arrancar.
            support.validateConfiguration();

            // Pasos 2 y 3: issuer identificado, firma/aud/ventana verificadas.
            Authentication authentication = support.authenticate(validRs256Token(ISSUER));
            assertThat(authentication).isNotNull();
            assertThat(authentication.isAuthenticated()).isTrue();
            assertThat(authentication.getName()).isEqualTo("userTest");
            assertThat(provider.calls()).isEqualTo(1);

            // Paso 2 (AC-004): si el issuer no está en la allowlist, se rechaza SIN resolver claves.
            assertThatThrownBy(() -> support.authenticate(validRs256Token(OTHER_ISSUER)))
                    .as("un issuer fuera de la allowlist se rechaza")
                    .isInstanceOf(AuthenticationException.class);
            assertThat(provider.calls())
                    .as("el issuer se resuelve antes de resolver claves")
                    .isEqualTo(1);
        });
    }

    @Test
    @DisplayName("Main Flow: GIVEN una aplicación sin allowlist declarada WHEN se configura THEN no publica ningún soporte OIDC (no rompe el modo local de FEAT-0013)")
    void testMainFlow_withoutIssuerPropertiesNoOidcSupportIsPublished() {
        new ApplicationContextRunner()
                .withUserConfiguration(BssOidcCoreConfig.class)
                .withBean(OidcJwkSetProvider.class, () -> provider)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(BssOidcSupport.class);
                });
    }

    // ---------------------------------------------------------------- helpers

    private static String validRs256Token(String issuer) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(AUDIENCE)
                .subject("userTest")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(KID).build(),
                    claims);
            jwt.sign(new RSASSASigner(RSA_KEY.getPrivate()));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("no se pudo firmar el token de prueba", ex);
        }
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("no se pudo generar el par RSA de prueba", ex);
        }
    }

    /** Provider de claves estático y contador: cero red, y evidencia de cuántas veces se resolvió. */
    private static final class StaticJwkSetProvider implements OidcJwkSetProvider {

        private final JWKSet jwkSet;
        private final AtomicInteger calls = new AtomicInteger();

        StaticJwkSetProvider() {
            this.jwkSet = new JWKSet(new RSAKey.Builder((RSAPublicKey) RSA_KEY.getPublic())
                    .keyID(KID)
                    .build());
        }

        @Override
        public JWKSet jwkSetFor(OidcIssuer issuer) {
            calls.incrementAndGet();
            return jwkSet;
        }

        int calls() {
            return calls.get();
        }
    }
}
