package com.bss.autoconfigtest;

import com.bss.security.core.exception.BssSecurityExceptionHandler;
import com.bss.security.core.service.JwtTokenService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FIX-0001 — AC-008 / BR-003: verifica la autoconfiguración REAL, sin component scan.
 *
 * Este es el test que hubiera detectado el defecto original: con
 * {@code scanBasePackages} el advice aparecía por escaneo y los tests pasaban,
 * mientras que un consumidor sin ese scan recibía 500 en lugar de 401.
 */
@SpringBootTest(classes = AutoConfigOnlyApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=esta-es-una-clave-secreta-muy-larga-y-segura-para-jwt-256-bits",
        "bss.security.cache.enabled=false"
})
class AutoConfigurationWiringTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private ApplicationContext context;

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private JwtTokenService jwtTokenService;

    /** Ver {@code SecurityHttpContractTest}: HttpURLConnection falla con 401 + POST. */
    @org.junit.jupiter.api.BeforeEach
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
    @DisplayName("BR-003: GIVEN la autoconfiguración sola WHEN arranca THEN el advice de errores queda registrado")
    void testBR003_exceptionHandlerRegisteredByAutoConfiguration() {
        assertThat(context.getBeansOfType(BssSecurityExceptionHandler.class))
                .as("El advice debe ser un bean creado por BssSecurityAutoConfiguration")
                .hasSize(1);
    }

    @Test
    @DisplayName("AC-008: GIVEN una app sin scan de com.bss.security WHEN falla el refresh THEN 401 con BssErrorResponse")
    void testAC008_errorSchemaWorksWithoutComponentScan() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> response = rest.exchange("/api/auth/refresh", HttpMethod.POST,
                new HttpEntity<>("{\"refreshToken\":\"no-existe\"}", headers), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        JsonNode json = mapper.readTree(response.getBody());
        assertThat(json.get("path").asText()).isEqualTo("/api/auth/refresh");
        assertThat(json.get("error").asText()).isEqualTo("Unauthorized");
    }

    @Test
    @DisplayName("AC-002: GIVEN un usuario sin rol admin WHEN invoca /api/bss/config THEN 403 con el schema estándar")
    void testAC002_forbiddenUsesStandardSchemaWithoutComponentScan() throws Exception {
        String token = jwtTokenService.generateToken("userTest", List.of("ROLE_USER"));

        ResponseEntity<String> response = get("/api/bss/config", token);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        JsonNode json = mapper.readTree(response.getBody());
        assertThat(json.get("status").asInt()).isEqualTo(403);
        assertThat(json.get("path").asText()).isEqualTo("/api/bss/config");
    }
}
