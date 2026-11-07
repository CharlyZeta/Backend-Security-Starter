package com.bss.security.core.oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Propiedades del núcleo OIDC (FEAT-0014).
 *
 * <pre>
 * bss:
 *   security:
 *     oidc:
 *       provider: custom        # default; el mismo valor que consume BssIdentitySelector
 *       issuers:
 *         - issuer: https://login.example.com/tenant
 *           algorithms: [RS256]
 *           audiences: [api-bss]
 *           clock-skew: 60s     # default 60s, máximo 300s
 *           jwks-uri: https://login.example.com/tenant/discovery/v2.0/keys
 * </pre>
 *
 * <p>{@code provider} tiene default {@code custom} porque el núcleo OIDC es genérico: el
 * proveedor concreto (entra, okta, …) sólo aporta defaults de configuración. La allowlist
 * arranca vacía y su ausencia es error de configuración cuando el modo es {@code oidc}
 * (ver {@link OidcIdentitySupport#validateConfiguration()}).
 *
 * <p>Se expone como bean JavaBean (getters/setters) para que Spring Boot haga
 * {@code binding} relajado, y además con accessors estilo record ({@link #provider()} /
 * {@link #issuers()}) para uso programático y tests.
 */
@ConfigurationProperties(prefix = "bss.security.oidc")
public class OidcProperties {

    /** Proveedor por defecto del núcleo genérico. */
    public static final String DEFAULT_PROVIDER = "custom";

    private String provider = DEFAULT_PROVIDER;

    private List<OidcIssuer> issuers = new ArrayList<>();

    public OidcProperties() {
    }

    public OidcProperties(String provider, List<OidcIssuer> issuers) {
        this.provider = provider;
        setIssuers(issuers);
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public List<OidcIssuer> getIssuers() {
        return issuers;
    }

    public void setIssuers(List<OidcIssuer> issuers) {
        this.issuers = issuers == null ? new ArrayList<>() : new ArrayList<>(issuers);
    }

    /** Accessor estilo record: el proveedor nunca es {@code null} ni vacío. */
    public String provider() {
        return provider == null || provider.isBlank() ? DEFAULT_PROVIDER : provider;
    }

    /** Accessor estilo record: copia inmutable de la allowlist configurada. */
    public List<OidcIssuer> issuers() {
        return List.copyOf(issuers);
    }
}
