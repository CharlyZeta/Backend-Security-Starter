package com.bss.autoconfigtest;

import com.bss.testfixtures.IncompleteCustomModuleConfig;
import com.bss.testfixtures.OidcModuleConfig;
import com.bss.testfixtures.TestTokens;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FEAT-0013 — fail-fast del arranque: AC-003, AC-008, AF-01, AF-02 y BR-004.
 * Cada caso levanta un contexto real con configuración incoherente y verifica el mensaje.
 */
class IdentityModeFailFastTest {

    private static void start(Map<String, Object> properties, Class<?>... sources) {
        Map<String, Object> defaults = new HashMap<>(properties);
        defaults.put("server.port", "0");
        defaults.put("bss.security.jwt.secret", TestTokens.SECRET);

        new SpringApplicationBuilder(sources)
                .web(WebApplicationType.SERVLET)
                .properties(defaults)
                .run();
    }

    @Test
    @DisplayName("AC-003/AF-01: GIVEN mode=oidc sin módulo OIDC WHEN arranca THEN falla nombrando la dependencia")
    void testAC003_oidcWithoutModuleFailsAtStartup() {
        assertThatThrownBy(() -> start(Map.of("bss.security.mode", "oidc",
                "bss.security.oidc.provider", "entra"), AutoConfigOnlyApp.class))
                .hasStackTraceContaining("backend-security-oidc");
    }

    @Test
    @DisplayName("AC-008: GIVEN un mode inválido WHEN arranca THEN falla listando los valores admitidos")
    void testAC008_invalidModeFailsAtStartup() {
        assertThatThrownBy(() -> start(Map.of("bss.security.mode", "entra"), AutoConfigOnlyApp.class))
                .hasStackTraceContaining("Valores admitidos: local, oidc");
    }

    @Test
    @DisplayName("AF-02/BR-003: GIVEN el módulo OIDC presente y sin mode WHEN arranca THEN falla por ambigüedad")
    void testAF02_modulePresentWithoutModeFailsAtStartup() {
        assertThatThrownBy(() -> start(Map.of(), AutoConfigOnlyApp.class, OidcModuleConfig.class))
                .hasStackTraceContaining("no está declarado");
    }

    @Test
    @DisplayName("BR-004: GIVEN mode=oidc con un provider que no existe WHEN arranca THEN falla listando los disponibles")
    void testBR004_unknownProviderFailsAtStartup() {
        assertThatThrownBy(() -> start(Map.of("bss.security.mode", "oidc",
                "bss.security.oidc.provider", "okta"), AutoConfigOnlyApp.class, OidcModuleConfig.class))
                .hasStackTraceContaining("Disponibles: test");
    }

    @Test
    @DisplayName("AF-05: GIVEN provider=custom sin configuración mínima WHEN arranca THEN falla indicando qué falta")
    void testAF05_incompleteProviderConfigurationFailsAtStartup() {
        assertThatThrownBy(() -> start(Map.of("bss.security.mode", "oidc",
                "bss.security.oidc.provider", "custom"), AutoConfigOnlyApp.class, IncompleteCustomModuleConfig.class))
                .hasStackTraceContaining("requiere declarar issuers, audiences y algorithms");
    }
}
