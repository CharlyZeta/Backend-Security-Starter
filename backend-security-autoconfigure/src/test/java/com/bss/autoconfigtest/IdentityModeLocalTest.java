package com.bss.autoconfigtest;

import com.bss.security.core.controller.BssAuthController;
import com.bss.security.core.identity.OidcAuthenticationFilter;
import com.bss.testfixtures.OidcModuleConfig;
import com.bss.testfixtures.TestOidcSupport;
import com.bss.testfixtures.TestTokens;
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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FEAT-0013 — modo local con el módulo OIDC presente: AC-001, AC-002, AC-006.
 */
@SpringBootTest(classes = {AutoConfigOnlyApp.class, OidcModuleConfig.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "bss.security.jwt.secret=" + TestTokens.SECRET,
        "bss.security.mode=local"
})
class IdentityModeLocalTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private TestRestTemplate rest;

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
    @DisplayName("AC-002: GIVEN mode=local y módulo OIDC presente WHEN arranca THEN no registra el filtro OIDC y conserva el refresh propio")
    void testAC002_localModeIgnoresAvailableOidcModule() {
        assertThat(context.getBeansOfType(OidcAuthenticationFilter.class)).isEmpty();
        assertThat(context.getBeansOfType(BssAuthController.class)).hasSize(1);
    }

    @Test
    @DisplayName("AC-001/BR-001: GIVEN mode=local WHEN llega un token HS256 válido THEN autentica")
    void testAC001_localHs256TokenAuthenticates() {
        String token = TestTokens.hs256("adminTest", "ROLE_BSS_ADMIN");

        assertThat(get("/api/bss/config", token).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    @DisplayName("AC-006: GIVEN mode=local WHEN llega un token RS256 válido de un IdP THEN 401")
    void testAC006_rs256TokenRejectedInLocalMode() {
        String rs256 = new TestOidcSupport().validRs256Token("userTest");

        assertThat(get("/api/bss/config", rs256).getStatusCode().value()).isEqualTo(401);
    }
}
