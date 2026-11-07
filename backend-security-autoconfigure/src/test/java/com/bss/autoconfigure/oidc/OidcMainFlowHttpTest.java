package com.bss.autoconfigure.oidc;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.TestPropertySource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FEAT-0014 — Main Flow funcional de punta a punta (HTTP real).
 *
 * <p>Usa la autoconfiguración real del starter en modo {@code oidc} y un contenedor embebido
 * ({@code RANDOM_PORT}), porque el status final (200/401) solo se puede verificar con el
 * despacho real (ver {@code stack.md} §5). El {@link OidcJwkSetProvider} de prueba devuelve un
 * JWKS estático en memoria: no hay red.
 *
 * <p>Recorre los pasos del Main Flow: allowlist declarada → issuer del token identificado antes
 * de pedir claves → firma/aud/ventana validadas → request autenticada (o 401 genérico).
 */
@SpringBootTest(classes = OidcMainFlowHttpTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=" + OidcMainFlowHttpTest.SECRET,
        "bss.security.mode=oidc",
        "bss.security.oidc.provider=" + OidcMainFlowHttpTest.PROVIDER,
        "bss.security.oidc.issuers[0].issuer=" + OidcMainFlowHttpTest.ISSUER,
        "bss.security.oidc.issuers[0].algorithms[0]=RS256",
        "bss.security.oidc.issuers[0].audiences[0]=" + OidcMainFlowHttpTest.AUDIENCE,
        "bss.security.oidc.issuers[0].clock-skew=60s",
        "bss.security.oidc.issuers[0].jwks-uri=" + OidcMainFlowHttpTest.ISSUER + "/jwks.json"
})
class OidcMainFlowHttpTest {

    static final String SECRET = "esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits";
    static final String PROVIDER = "custom";
    static final String ISSUER = "https://idp.test.local";
    static final String OTHER_ISSUER = "https://otro-idp.test.local";
    static final String AUDIENCE = "bss-api";
    static final String OTHER_AUDIENCE = "otra-api";
    static final String KID = "rsa-key-1";

    private static final KeyPair RSA_KEY = generateRsaKeyPair();
    private static final StaticJwkSetProvider PROVIDER_BEAN = new StaticJwkSetProvider();

    @Autowired
    private TestRestTemplate rest;

    @BeforeEach
    void setUp() {
        PROVIDER_BEAN.reset();
        rest.getRestTemplate().setRequestFactory(
                new org.springframework.http.client.JdkClientHttpRequestFactory());
    }

    // ------------------------------------------------------------ Main Flow

    @Test
    @DisplayName("Main Flow (HTTP): GIVEN un token RS256 de un issuer declarado WHEN se invoca un endpoint protegido THEN 200 y request autenticada")
    void testMainFlow_validTokenReturns200() {
        ResponseEntity<String> response = get("/api/test", token(ISSUER, AUDIENCE));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo("Allowed!");
        assertThat(PROVIDER_BEAN.calls())
                .as("se resolvieron claves del issuer identificado")
                .isPositive();
    }

    @Test
    @DisplayName("Main Flow (HTTP): GIVEN un token con iss no declarado WHEN se invoca THEN 401 sin resolver claves")
    void testMainFlow_unknownIssuerReturns401WithoutResolvingKeys() {
        ResponseEntity<String> response = get("/api/test", token(OTHER_ISSUER, AUDIENCE));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(PROVIDER_BEAN.calls())
                .as("el issuer se identifica antes de resolver claves (paso 2)")
                .isZero();
    }

    @Test
    @DisplayName("Main Flow (HTTP): GIVEN un token con aud no permitida WHEN se invoca THEN 401")
    void testMainFlow_wrongAudienceReturns401() {
        ResponseEntity<String> response = get("/api/test", token(ISSUER, OTHER_AUDIENCE));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("AF-05 (HTTP): GIVEN un request sin header Authorization WHEN se invoca THEN 401")
    void testAF05_missingAuthorizationHeaderReturns401() {
        ResponseEntity<String> response = get("/api/test", null);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(PROVIDER_BEAN.calls())
                .as("sin header no se intenta validar ningún token")
                .isZero();
    }

    // ------------------------------------------------------------- helpers

    private ResponseEntity<String> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    private static String token(String issuer, String audience) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
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

    // ------------------------------------------------------------ test app

    /** App de prueba con la autoconfiguración real del starter y claves estáticas. */
    @SpringBootApplication
    static class TestApp {

        @Bean
        UserDetailsService userDetailsService() {
            return username -> {
                if ("userTest".equals(username)) {
                    return User.withUsername("userTest").password("{noop}pw").roles("USER").build();
                }
                throw new UsernameNotFoundException("User not found: " + username);
            };
        }

        @Bean
        OidcJwkSetProvider oidcJwkSetProvider() {
            return PROVIDER_BEAN;
        }
    }

    /** Provider de claves estático y contador: cero red y evidencia de resolución de claves. */
    static final class StaticJwkSetProvider implements OidcJwkSetProvider {

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

        void reset() {
            calls.set(0);
        }
    }
}
