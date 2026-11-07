package com.bss.security.core.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Fixtures de FEAT-0014 sin red y sin archivos de claves.
 *
 * <p>Todo se genera en memoria: pares RSA (2048) y EC (P-256/P-384) con el JDK, un
 * {@link JWKSet} estático con las claves públicas y tokens de prueba firmados con Nimbus
 * ({@link RSASSASigner}/{@link ECDSASigner}). El {@link OidcJwkSetProvider} de prueba cuenta
 * cuántas veces se resolvieron claves; AC-004 lo necesita para demostrar que un {@code iss}
 * desconocido no dispara resolución de claves.
 *
 * <p>Esta clase concentra a propósito la construcción de los tipos de la API (issuer,
 * properties, tokens): si el implementador cambia una firma, se ajusta acá y no en cada test.
 */
final class OidcTestFixtures {

    static final String ISSUER = "https://idp.test.local";
    static final String OTHER_ISSUER = "https://otro-idp.test.local";
    static final String AUDIENCE = "bss-api";
    static final String OTHER_AUDIENCE = "otra-api";
    static final String PROVIDER = "custom";
    static final String JWKS_URI = ISSUER + "/jwks.json";

    static final String KID_RSA = "rsa-key-1";
    static final String KID_RSA_BACKUP = "rsa-key-2";
    static final String KID_EC256 = "ec-p256-key-1";
    static final String KID_EC384 = "ec-p384-key-1";

    /** Par RSA principal: firma RS y PS, y también es la "clave pública" del ataque HS256. */
    static final KeyPair RSA_KEY = rsaKeyPair();
    /** Segundo par RSA del mismo issuer: sirve para BR-004 (el kid elige la clave, no el alg). */
    static final KeyPair RSA_BACKUP_KEY = rsaKeyPair();
    /** Par EC P-256: ES256. */
    static final KeyPair EC256_KEY = ecKeyPair("secp256r1");
    /** Par EC P-384: ES384. */
    static final KeyPair EC384_KEY = ecKeyPair("secp384r1");

    private OidcTestFixtures() {
    }

    // ------------------------------------------------------------- configuración

    static OidcIssuer issuer(String issuer, List<String> algorithms, List<String> audiences,
                             Duration clockSkew) {
        return new OidcIssuer(issuer, algorithms, audiences, clockSkew, issuer + "/jwks.json");
    }

    /** Issuer canónico de los tests: RS256 y audiencia {@link #AUDIENCE}, skew 60 s. */
    static OidcIssuer rsaIssuer() {
        return issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), Duration.ofSeconds(60));
    }

    /** Issuer con ES256 habilitado (AC-002). */
    static OidcIssuer es256Issuer() {
        return issuer(ISSUER, List.of("ES256"), List.of(AUDIENCE), Duration.ofSeconds(60));
    }

    /**
     * Propiedades de FEAT-0014 con un único proveedor lógico y la lista de issuers indicada.
     * La forma del constructor se centraliza acá.
     */
    static OidcProperties properties(OidcIssuer... issuers) {
        return new OidcProperties(PROVIDER, List.of(issuers));
    }

    /** Decoder compuesto (allowlist completa) contra el que se validan los tokens. */
    static OidcJwtDecoder decoder(OidcIssuer... issuers) {
        return new OidcJwtDecoder(List.of(issuers), countingProvider(standardJwkSet()));
    }

    static OidcJwtDecoder decoder(OidcJwkSetProvider provider, OidcIssuer... issuers) {
        return new OidcJwtDecoder(List.of(issuers), provider);
    }

    // ------------------------------------------------------------------- JWKS

    static JWK publicJwk(String kid, KeyPair pair) {
        if (pair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
            return new RSAKey.Builder(rsaPublicKey).keyID(kid).build();
        }
        if (pair.getPublic() instanceof ECPublicKey ecPublicKey) {
            Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
            return new ECKey.Builder(curve, ecPublicKey).keyID(kid).build();
        }
        throw new IllegalArgumentException("tipo de clave no soportado: " + pair.getPublic().getAlgorithm());
    }

    static JWKSet jwkSet(JWK... keys) {
        return new JWKSet(List.of(keys));
    }

    static JWKSet emptyJwkSet() {
        return new JWKSet(List.of());
    }

    /** JWKS con las cuatro claves públicas conocidas. */
    static JWKSet standardJwkSet() {
        return jwkSet(
                publicJwk(KID_RSA, RSA_KEY),
                publicJwk(KID_RSA_BACKUP, RSA_BACKUP_KEY),
                publicJwk(KID_EC256, EC256_KEY),
                publicJwk(KID_EC384, EC384_KEY));
    }

    static CountingJwkSetProvider countingProvider(JWKSet jwkSet) {
        return new CountingJwkSetProvider(jwkSet);
    }

    static CountingJwkSetProvider countingProvider(Map<String, JWKSet> byIssuer) {
        return new CountingJwkSetProvider(byIssuer, emptyJwkSet());
    }

    // ---------------------------------------------------------------- tokens

    static JWTClaimsSet.Builder claims(String issuer, String audience) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("userTest")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))));
    }

    /** Claims válidos salvo el issuer, que se omite (AF-01). */
    static JWTClaimsSet claimsWithoutIssuer(String audience) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .audience(audience)
                .subject("userTest")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .build();
    }

    /** Claims válidos salvo la audiencia, que se omite (BR-005). */
    static JWTClaimsSet claimsWithoutAudience(String issuer) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("userTest")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .build();
    }

    static String token(JWSAlgorithm algorithm, String kid, KeyPair signingKey, JWTClaimsSet claims)
            throws JOSEException {
        SignedJWT jwt = new SignedJWT(header(algorithm, kid), claims);
        jwt.sign(signer(algorithm, signingKey));
        return jwt.serialize();
    }

    /** Token firmado para el issuer y la audiencia canónicos. */
    static String token(JWSAlgorithm algorithm, String kid, KeyPair signingKey) throws JOSEException {
        return token(algorithm, kid, signingKey, claims(ISSUER, AUDIENCE).build());
    }

    static JWSHeader header(JWSAlgorithm algorithm, String kid) {
        return new JWSHeader.Builder(algorithm)
                .type(JOSEObjectType.JWT)
                .keyID(kid)
                .build();
    }

    static JWSSigner signer(JWSAlgorithm algorithm, KeyPair signingKey) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(algorithm)) {
            return new ECDSASigner((ECPrivateKey) signingKey.getPrivate());
        }
        // RS y PS comparten el proveedor RSA-PKCS#1 / RSA-PSS de Nimbus.
        return new RSASSASigner(signingKey.getPrivate());
    }

    /**
     * AC-007: JWS con {@code alg=HS256} cuya clave HMAC es el material público RSA. Un validador
     * que mire solo la firma lo aceptaría; el decoder tiene que rechazarlo por allowlist de alg.
     */
    static String hs256TokenSignedWithRsaPublicKey(KeyPair rsaKeyPair, String issuer, String audience)
            throws JOSEException {
        SecretKeySpec secret = new SecretKeySpec(
                ((RSAPublicKey) rsaKeyPair.getPublic()).getEncoded(), "HmacSHA256");
        SignedJWT jwt = new SignedJWT(header(JWSAlgorithm.HS256, KID_RSA),
                claims(issuer, audience).build());
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    /** AC-006: JWS sin firma, {@code alg=none}, armado a mano (Nimbus no firma con NONE). */
    static String noneToken(String issuer, String audience) {
        String header = Base64URL.encode("{\"alg\":\"none\",\"typ\":\"JWT\"}").toString();
        String payload = Base64URL.encode(
                claims(issuer, audience).build().toJSONObject().toString()).toString();
        return header + "." + payload + ".";
    }

    // --------------------------------------------------------------- asserts

    /**
     * Rechazo genérico de un token: el contrato de {@link JwtDecoder} usa
     * {@link JwtException}, y el compuesto de FEAT-0014 rechaza temprano (iss/alg) con una
     * {@link AuthenticationException}. Ambos son "rechazo" válido; lo que nunca es válido es
     * aceptar.
     */
    static void assertRejected(JwtDecoder decoder, String token) {
        assertThatThrownBy(() -> decoder.decode(token))
                .as("el token debe rechazarse")
                .isInstanceOfAny(JwtException.class, AuthenticationException.class);
    }

    // --------------------------------------------------------------- helpers

    static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("no se pudo generar el par RSA de prueba", ex);
        }
    }

    static KeyPair ecKeyPair(String curveName) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curveName));
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("no se pudo generar el par EC de prueba (" + curveName + ")", ex);
        }
    }
}
