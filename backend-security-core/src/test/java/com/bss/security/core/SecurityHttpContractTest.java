package com.bss.security.core;

import com.bss.security.core.service.JwtTokenService;
import com.bss.security.core.testapp.TestSecurityApp;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Contrato HTTP de seguridad — FIX-0001.
 *
 * Corre contra un contenedor real ({@code RANDOM_PORT}) a propósito: el defecto
 * original (403/500 enmascarados como 401) solo aparece con el despacho de error
 * real, que MockMvc no reproduce.
 */
@SpringBootTest(classes = TestSecurityApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits",
        "bss.security.jwt.expiration=3600",
        "bss.security.jwt.refresh.expiration=604800",
        "bss.security.cache.enabled=false"
})
class SecurityHttpContractTest {

    private static final String SECRET = "esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits";
    private static final String OTHER_SECRET = "otra-clave-completamente-distinta-de-32-o-mas-caracteres";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private TestRestTemplate rest;

    @SpyBean
    private JwtTokenService jwtTokenService;

    /**
     * El cliente por defecto (HttpURLConnection) lanza {@code HttpRetryException}
     * ante un 401 en POST con body. El cliente del JDK ({@code java.net.http})
     * no tiene ese comportamiento y no agrega dependencias.
     */
    @org.junit.jupiter.api.BeforeEach
    void useModernHttpClient() {
        rest.getRestTemplate().setRequestFactory(
                new org.springframework.http.client.JdkClientHttpRequestFactory());
    }

    // ------------------------------------------------------------------ helpers

    private ResponseEntity<String> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    private ResponseEntity<String> postJson(String path, String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange(path, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        assertThat(response.getBody()).isNotBlank();
        return mapper.readTree(response.getBody());
    }

    private String sign(String subject, String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000))
                .signWith(key)
                .compact();
    }

    // -------------------------------------------------------------------- ACs

    @Test
    @DisplayName("AC-001: GIVEN un token con firma inválida WHEN se invoca un endpoint protegido THEN 401 con el path real")
    void testAC001_invalidSignatureReturns401WithRealPath() throws Exception {
        ResponseEntity<String> response = get("/api/test", sign("userTest", OTHER_SECRET));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode json = body(response);
        assertThat(json.get("status").asInt()).isEqualTo(401);
        assertThat(json.get("error").asText()).isEqualTo("Unauthorized");
        assertThat(json.get("path").asText()).isEqualTo("/api/test");
    }

    @Test
    @DisplayName("AC-002: GIVEN un usuario sin el rol requerido WHEN invoca /api/bss/config THEN 403 con BssErrorResponse")
    void testAC002_authenticatedWithoutRoleReturns403WithStandardSchema() throws Exception {
        String token = jwtTokenService.generateToken("userTest", List.of("ROLE_USER"));

        ResponseEntity<String> response = get("/api/bss/config", token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        JsonNode json = body(response);
        assertThat(json.get("status").asInt()).isEqualTo(403);
        assertThat(json.get("error").asText()).isEqualTo("Forbidden");
        assertThat(json.get("path").asText()).isEqualTo("/api/bss/config");
    }

    @Test
    @DisplayName("AC-003/BR-007: GIVEN un token de usuario inexistente WHEN se invoca un endpoint THEN 401 sin filtrar internals")
    void testAC003_unknownUserTokenReturns401WithoutInternals() throws Exception {
        ResponseEntity<String> response = get("/api/test", sign("ghost", SECRET));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode json = body(response);
        assertThat(json.get("path").asText()).isEqualTo("/api/test");
        assertThat(response.getBody())
                .doesNotContain("Exception")
                .doesNotContain("java.")
                .doesNotContain("ghost");
    }

    @Test
    @DisplayName("AC-004: GIVEN un refresh token inexistente WHEN se invoca /api/auth/refresh THEN 401 con el path real")
    void testAC004_unknownRefreshTokenReturns401WithRealPath() throws Exception {
        ResponseEntity<String> response = postJson("/api/auth/refresh", "{\"refreshToken\":\"no-existe\"}");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode json = body(response);
        assertThat(json.get("path").asText()).isEqualTo("/api/auth/refresh");
        assertThat(json.get("status").asInt()).isEqualTo(401);
    }

    @Test
    @DisplayName("AC-005: GIVEN un body sin refreshToken WHEN se invoca refresh THEN 400 con BssErrorResponse")
    void testAC005_missingRefreshTokenReturns400() throws Exception {
        ResponseEntity<String> response = postJson("/api/auth/refresh", "{}");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode json = body(response);
        assertThat(json.get("status").asInt()).isEqualTo(400);
        assertThat(json.get("path").asText()).isEqualTo("/api/auth/refresh");
    }

    @Test
    @DisplayName("AC-006/BR-006: GIVEN una respuesta de seguridad WHEN se lee timestamp THEN es ISO-8601, no un array")
    void testAC006_timestampIsIso8601() throws Exception {
        ResponseEntity<String> response = get("/api/test", sign("userTest", OTHER_SECRET));
        JsonNode timestamp = body(response).get("timestamp");

        assertThat(timestamp.isTextual())
                .as("timestamp debe ser string ISO-8601, no array numérico")
                .isTrue();
        assertThatNoException().isThrownBy(() -> LocalDateTime.parse(timestamp.asText()));
    }

    @Test
    @DisplayName("AC-007/BR-002: GIVEN un endpoint que lanza una excepción WHEN se invoca THEN 500 y no 401")
    void testAC007_unhandledExceptionReturns500NotUnauthorized() throws Exception {
        String token = jwtTokenService.generateToken("userTest", List.of("ROLE_USER"));

        ResponseEntity<String> response = get("/api/boom", token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("AC-009/BR-005: GIVEN un request autenticado WHEN pasa por el filtro THEN el token se parsea una sola vez")
    void testAC009_tokenIsParsedOncePerRequest() {
        String token = jwtTokenService.generateToken("userTest", List.of("ROLE_USER"));
        clearInvocations(jwtTokenService);

        ResponseEntity<String> response = get("/api/test", token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(jwtTokenService, times(1)).parseClaims(anyString());
    }

    @Test
    @DisplayName("BR-002: GIVEN el despacho de error WHEN se invoca /error directamente THEN no exige autenticación")
    void testBR002_errorDispatchDoesNotRequireAuthentication() {
        ResponseEntity<String> response = get("/error", null);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("BR-004: GIVEN 401, 403 y 400 WHEN se comparan los bodies THEN comparten el schema BssErrorResponse")
    void testBR004_allSecurityResponsesShareSchema() throws Exception {
        String userToken = jwtTokenService.generateToken("userTest", List.of("ROLE_USER"));

        List<ResponseEntity<String>> responses = List.of(
                get("/api/test", sign("userTest", OTHER_SECRET)),
                get("/api/bss/config", userToken),
                postJson("/api/auth/refresh", "{}")
        );

        for (ResponseEntity<String> response : responses) {
            JsonNode json = body(response);
            assertThat(json.hasNonNull("status")).isTrue();
            assertThat(json.hasNonNull("error")).isTrue();
            assertThat(json.hasNonNull("message")).isTrue();
            assertThat(json.hasNonNull("path")).isTrue();
            assertThat(json.hasNonNull("timestamp")).isTrue();
        }
    }
}
