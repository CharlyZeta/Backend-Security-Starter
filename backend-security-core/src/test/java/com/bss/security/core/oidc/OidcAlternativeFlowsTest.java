package com.bss.security.core.oidc;

import com.bss.security.core.config.JwtAuthenticationEntryPoint;
import com.bss.security.core.identity.BssOidcSupport;
import com.bss.security.core.identity.OidcAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.bss.security.core.oidc.OidcTestFixtures.AUDIENCE;
import static com.bss.security.core.oidc.OidcTestFixtures.EC256_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_EC256;
import static com.bss.security.core.oidc.OidcTestFixtures.KID_RSA;
import static com.bss.security.core.oidc.OidcTestFixtures.OTHER_AUDIENCE;
import static com.bss.security.core.oidc.OidcTestFixtures.OTHER_ISSUER;
import static com.bss.security.core.oidc.OidcTestFixtures.RSA_KEY;
import static com.bss.security.core.oidc.OidcTestFixtures.assertRejected;
import static com.bss.security.core.oidc.OidcTestFixtures.claims;
import static com.bss.security.core.oidc.OidcTestFixtures.claimsWithoutIssuer;
import static com.bss.security.core.oidc.OidcTestFixtures.countingProvider;
import static com.bss.security.core.oidc.OidcTestFixtures.decoder;
import static com.bss.security.core.oidc.OidcTestFixtures.hs256TokenSignedWithRsaPublicKey;
import static com.bss.security.core.oidc.OidcTestFixtures.issuer;
import static com.bss.security.core.oidc.OidcTestFixtures.noneToken;
import static com.bss.security.core.oidc.OidcTestFixtures.rsaIssuer;
import static com.bss.security.core.oidc.OidcTestFixtures.standardJwkSet;
import static com.bss.security.core.oidc.OidcTestFixtures.token;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * FEAT-0014 — Alternative Flows (AF-01..AF-05).
 *
 * <p>AF-01..AF-04 se verifican contra el decoder compuesto; AF-05 (falta del header
 * {@code Authorization}) se verifica sobre el filtro OIDC real más el entry point: sin header no
 * se intenta validar ningún token y la request termina en 401.
 */
class OidcAlternativeFlowsTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    // ------------------------------------------------------------------ AF-01

    @Test
    @DisplayName("AF-01: GIVEN un token con iss ausente o fuera de la allowlist WHEN se valida THEN se rechaza sin intentar otro issuer")
    void testAF01_missingOrUnknownIssuerIsRejectedWithoutTryingAnotherIssuer() throws Exception {
        CountingJwkSetProvider provider = countingProvider(standardJwkSet());
        OidcJwtDecoder decoder = decoder(provider, rsaIssuer());

        String missingIssuer = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY,
                claimsWithoutIssuer(AUDIENCE));
        String unknownIssuer = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY,
                claims(OTHER_ISSUER, AUDIENCE).build());

        assertThatThrownBy(() -> decoder.decode(missingIssuer))
                .as("sin claim iss no hay issuer que resolver")
                .isInstanceOf(AuthenticationException.class);
        assertThatThrownBy(() -> decoder.decode(unknownIssuer))
                .as("el issuer desconocido no cae al issuer declarado")
                .isInstanceOf(AuthenticationException.class);

        assertThat(provider.calls())
                .as("ningún intento de issuer debe resolver claves")
                .isZero();
    }

    // ------------------------------------------------------------------ AF-02

    @Test
    @DisplayName("AF-02: GIVEN un alg distinto del fijado para el issuer (incluidos none y HS*) WHEN se valida THEN se rechaza")
    void testAF02_algDifferentFromIssuerIsRejectedIncludingNoneAndHsStar() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer()); // el issuer fija RS256

        List<String> rejected = List.of(
                noneToken(ISSUER, AUDIENCE),
                hs256TokenSignedWithRsaPublicKey(RSA_KEY, ISSUER, AUDIENCE),
                token(JWSAlgorithm.RS384, KID_RSA, RSA_KEY),
                token(JWSAlgorithm.ES256, KID_EC256, EC256_KEY));

        for (String token : rejected) {
            assertRejected(decoder, token);
        }
    }

    // ------------------------------------------------------------------ AF-03

    @Test
    @DisplayName("AF-03: GIVEN un token cuya aud no incluye ninguna audiencia permitida WHEN se valida THEN se rechaza")
    void testAF03_audienceNotIncludedIsRejected() throws Exception {
        OidcJwtDecoder decoder = decoder(rsaIssuer());
        String token = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY,
                claims(ISSUER, OTHER_AUDIENCE).build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    // ------------------------------------------------------------------ AF-04

    @Test
    @DisplayName("AF-04: GIVEN un token vencido o aún no vigente fuera del skew del issuer WHEN se valida THEN se rechaza")
    void testAF04_expiredOrNotYetValidBeyondSkewIsRejected() throws Exception {
        Duration skew = Duration.ofSeconds(60);
        OidcJwtDecoder decoder = decoder(
                issuer(ISSUER, List.of("RS256"), List.of(AUDIENCE), skew));
        Instant now = Instant.now();

        JWTClaimsSet expiredClaims = claims(ISSUER, AUDIENCE)
                .issueTime(Date.from(now.minusSeconds(600)))
                .expirationTime(Date.from(now.minusSeconds(120)))
                .build();
        String expired = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, expiredClaims);

        JWTClaimsSet notYetValidClaims = claims(ISSUER, AUDIENCE)
                .notBeforeTime(Date.from(now.plusSeconds(120)))
                .build();
        String notYetValid = token(JWSAlgorithm.RS256, KID_RSA, RSA_KEY, notYetValidClaims);

        assertRejected(decoder, expired);
        assertRejected(decoder, notYetValid);
    }

    // ------------------------------------------------------------------ AF-05

    @Test
    @DisplayName("AF-05: GIVEN un request sin header Authorization WHEN pasa por el filtro OIDC THEN no se valida ningún token y la request termina en 401")
    void testAF05_missingAuthorizationHeaderDoesNotAttemptTokenValidation() throws Exception {
        BssOidcSupport support = mock(BssOidcSupport.class);
        OidcAuthenticationFilter filter = new OidcAuthenticationFilter(support);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        filter.doFilter(request, response,
                (servletRequest, servletResponse) -> chainInvoked.set(true));

        assertThat(chainInvoked).as("la request sigue la cadena hacia el entry point").isTrue();
        verifyNoInteractions(support);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        // Sin credenciales, el entry point responde 401 genérico con el desafío RFC 6750.
        new JwtAuthenticationEntryPoint(new ObjectMapper()).commence(
                request, response, new InsufficientAuthenticationException("Full authentication is required"));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
    }
}
