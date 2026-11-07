package com.bss.security.core.identity;

import com.bss.security.core.exception.BssConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FEAT-0013 — matriz de decisión del selector (BR-001..BR-004, AC-008).
 * Test unitario: no levanta contexto de Spring, así que corre en milisegundos.
 */
class BssIdentitySelectorTest {

    private static BssOidcSupport support(String provider) {
        return new BssOidcSupport() {
            @Override
            public String provider() {
                return provider;
            }

            @Override
            public Authentication authenticate(String bearerToken) {
                throw new BadCredentialsException("sin uso en este test");
            }
        };
    }

    private static BssIdentityProperties properties(String mode, String provider) {
        BssIdentityProperties properties = new BssIdentityProperties();
        properties.setMode(mode);
        properties.getOidc().setProvider(provider);
        return properties;
    }

    @Test
    @DisplayName("BR-001/AC-001: GIVEN sin mode y sin módulo OIDC WHEN se resuelve THEN LOCAL")
    void testBR001_withoutModeAndWithoutModuleIsLocal() {
        BssIdentitySelector selector = new BssIdentitySelector(properties(null, null), List.of());

        assertThat(selector.mode()).isEqualTo(BssIdentityMode.LOCAL);
    }

    @Test
    @DisplayName("BR-003/AF-02: GIVEN sin mode y con módulo OIDC WHEN se resuelve THEN falla por ambigüedad")
    void testBR003_withoutModeButModulePresentFails() {
        BssIdentitySelector selector = new BssIdentitySelector(properties(null, null), List.of(support("entra")));

        assertThatThrownBy(selector::mode)
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("no está declarado")
                .hasMessageContaining("entra");
    }

    @Test
    @DisplayName("AC-002/BR-002: GIVEN mode=local y módulo presente WHEN se resuelve THEN LOCAL y no elige soporte")
    void testAC002_localWinsOverAvailableModule() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("local", null), List.of(support("entra")));

        assertThat(selector.mode()).isEqualTo(BssIdentityMode.LOCAL);
        assertThatThrownBy(selector::support).isInstanceOf(BssConfigurationException.class);
    }

    @Test
    @DisplayName("BR-004/AC-003: GIVEN mode=oidc sin módulo WHEN se resuelve THEN falla nombrando la dependencia")
    void testAC003_oidcWithoutModuleFailsNamingDependency() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("oidc", "entra"), List.of());

        assertThatThrownBy(selector::mode)
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("backend-security-oidc");
    }

    @Test
    @DisplayName("BR-004: GIVEN mode=oidc con módulo y sin provider WHEN se resuelve THEN falla indicando que es obligatorio")
    void testBR004_oidcWithoutProviderFails() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("oidc", "  "), List.of(support("entra")));

        assertThatThrownBy(selector::mode)
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("bss.security.oidc.provider es obligatorio")
                .hasMessageContaining("entra");
    }

    @Test
    @DisplayName("BR-004: GIVEN un provider desconocido WHEN se resuelve THEN falla listando los disponibles")
    void testBR004_unknownProviderFailsListingAvailable() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("oidc", "okta"), List.of(support("entra")));

        assertThatThrownBy(selector::mode)
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("Proveedor OIDC desconocido")
                .hasMessageContaining("Disponibles: entra");
    }

    @Test
    @DisplayName("AC-008: GIVEN un mode inválido WHEN se resuelve THEN falla listando los valores admitidos")
    void testAC008_invalidModeListsAllowedValues() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("entra", null), List.of(support("entra")));

        assertThatThrownBy(selector::mode)
                .isInstanceOf(BssConfigurationException.class)
                .hasMessageContaining("Valores admitidos: local, oidc");
    }

    @Test
    @DisplayName("AC-004: GIVEN mode=oidc con provider válido WHEN se pide el soporte THEN devuelve el del provider")
    void testAC004_supportResolvesByProvider() {
        BssOidcSupport entra = support("entra");
        BssOidcSupport okta = support("okta");
        BssIdentitySelector selector = new BssIdentitySelector(properties("OIDC", "okta"), List.of(entra, okta));

        assertThat(selector.mode()).isEqualTo(BssIdentityMode.OIDC);
        assertThat(selector.support()).isSameAs(okta);
    }

    @Test
    @DisplayName("BR-006: GIVEN mode declarado en mayúsculas WHEN se resuelve THEN se acepta sin distinguir case")
    void testBR006_modeIsCaseInsensitive() {
        BssIdentitySelector selector = new BssIdentitySelector(properties("LOCAL", null), List.of());

        assertThat(selector.mode()).isEqualTo(BssIdentityMode.LOCAL);
    }
}
