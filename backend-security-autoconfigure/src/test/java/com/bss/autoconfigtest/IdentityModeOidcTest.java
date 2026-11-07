package com.bss.autoconfigtest;

import com.bss.security.core.controller.BssAuthController;
import com.bss.security.core.identity.OidcAuthenticationFilter;
import com.bss.testfixtures.TestOidcSupport;
import com.bss.testfixtures.TestTokens;
import com.bss.testfixtures.oidc.OidcTestApp;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FEAT-0013 — modo {@code oidc}: AC-004, AC-005, AC-007.
 *
 * <p>El soporte OIDC es un doble de prueba con validación RS256 real; el decoder de producción
 * lo aporta FEAT-0014. Lo que se verifica acá es el cableado del modo: qué filtro se registra,
 * qué endpoints desaparecen y que el token del otro modo no se intente validar.
 */
@SpringBootTest(classes = OidcTestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=" + TestTokens.SECRET,
        "bss.security.mode=oidc",
        "bss.security.oidc.provider=test"
})
class IdentityModeOidcTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private ApplicationContext context;

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private TestOidcSupport support;

    @BeforeEach
    void useModernHttpClient() {
        rest.getRestTemplate().setRequestFactory(
                new org.springframework.http.client.JdkClientHttpRequestFactory());
    }

    private ResponseEntity<String> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    @Test
    @DisplayName("AC-004: GIVEN mode=oidc con soporte WHEN arranca THEN registra el filtro OIDC y no los endpoints de refresh propios")
    void testAC004_oidcModeRegistersOidcFilterAndNoLocalRefreshEndpoints() {
        assertThat(context.getBeansOfType(OidcAuthenticationFilter.class)).hasSize(1);
        assertThat(context.getBeansOfType(BssAuthController.class)).isEmpty();
    }

    @Test
    @DisplayName("AC-005: GIVEN mode=oidc WHEN llega un token HS256 firmado con el secreto local THEN 401")
    void testAC005_localHs256TokenRejectedInOidcMode() {
        String hs256 = Jwts.builder()
                .subject("userTest")
                .signWith(Keys.hmacShaKeyFor(TestTokens.SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(get("/api/test", hs256).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("AC-007: GIVEN mode=oidc WHEN llega alg=HS256 firmado con la clave pública RSA THEN 401")
    void testAC007_algorithmConfusionRejected() {
        String confusion = Jwts.builder()
                .subject("userTest")
                .signWith(Keys.hmacShaKeyFor(support.publicKey().getEncoded()), Jwts.SIG.HS256)
                .compact();

        assertThat(get("/api/test", confusion).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Control positivo: un token RS256 válido del soporte OIDC autentica")
    void testRs256TokenIsAccepted() {
        ResponseEntity<String> response = get("/api/test", support.validRs256Token("userTest"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo("Allowed!");
    }

    @Test
    @DisplayName("Control: 401 con el schema estándar cuando el token OIDC es inválido")
    void testInvalidOidcTokenUsesStandardSchema() throws Exception {
        ResponseEntity<String> response = get("/api/test", "no-es-un-jwt");

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        JsonNode body = mapper.readTree(response.getBody());
        assertThat(body.get("path").asText()).isEqualTo("/api/test");
    }
}
