package com.bss.security.core.identity;

/**
 * Modo de validación de identidad de un despliegue (FEAT-0013).
 *
 * <p>{@link #LOCAL} valida los tokens que emite BSS (HS256 + refresh propio).
 * {@link #OIDC} valida tokens de un proveedor externo a través de {@link BssOidcSupport}.
 * Los dos modos son excluyentes en 1.x: no conviven por request.
 */
public enum BssIdentityMode {

    /** Tokens propios de BSS (HS256). Comportamiento histórico del starter. */
    LOCAL("local"),

    /** Tokens de un IdP externo (RS/ES/PS), resueltos por el módulo OIDC. */
    OIDC("oidc");

    private final String value;

    BssIdentityMode(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /** Valores admitidos en configuración, para mensajes de error. */
    public static String allowedValues() {
        return LOCAL.value + ", " + OIDC.value;
    }
}
