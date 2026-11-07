package com.bss.security.core.identity;

import com.bss.security.core.exception.BssConfigurationException;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resuelve el modo de identidad y falla rápido si la configuración es ambigua o incoherente
 * (FEAT-0013 · BR-001..BR-004).
 *
 * <p>Reglas:
 * <ul>
 *   <li>Sin {@code mode} declarado y sin soporte OIDC → {@link BssIdentityMode#LOCAL}.</li>
 *   <li>Sin {@code mode} declarado y con soporte OIDC → falla: la identidad no se infiere (BR-003).</li>
 *   <li>{@code mode=local} → local, aunque el módulo OIDC esté presente.</li>
 *   <li>{@code mode=oidc} sin soporte → falla nombrando la dependencia (BR-004).</li>
 *   <li>{@code mode=oidc} exige un {@code provider} que exista entre los soportes disponibles.</li>
 *   <li>Cualquier otro valor → falla listando los admitidos.</li>
 * </ul>
 */
public class BssIdentitySelector {

    public static final String MODULE_HINT = "backend-security-oidc";

    private final BssIdentityProperties properties;
    private final List<BssOidcSupport> supports;

    public BssIdentitySelector(BssIdentityProperties properties, List<BssOidcSupport> supports) {
        this.properties = properties;
        this.supports = supports == null ? List.of() : List.copyOf(supports);
    }

    /** Modo efectivo, validado. Lanza {@link BssConfigurationException} si la configuración no cierra. */
    public BssIdentityMode mode() {
        String declared = trimToNull(properties.getMode());

        if (declared == null) {
            if (!supports.isEmpty()) {
                throw new BssConfigurationException(
                        "bss.security.mode no está declarado y hay proveedores OIDC disponibles (" + providers() + "). "
                                + "La identidad no se elige por inferencia: declará bss.security.mode con uno de "
                                + BssIdentityMode.allowedValues() + ".");
            }
            return BssIdentityMode.LOCAL;
        }

        for (BssIdentityMode candidate : BssIdentityMode.values()) {
            if (candidate.value().equalsIgnoreCase(declared)) {
                return validate(candidate);
            }
        }

        throw new BssConfigurationException(
                "Valor inválido para bss.security.mode: '" + declared + "'. Valores admitidos: "
                        + BssIdentityMode.allowedValues() + ".");
    }

    /** Soporte OIDC del proveedor declarado. Solo válido en modo {@code oidc}. */
    public BssOidcSupport support() {
        BssIdentityMode mode = mode();
        if (mode != BssIdentityMode.OIDC) {
            throw new BssConfigurationException(
                    "No hay soporte OIDC en modo " + mode.value() + ": revisá bss.security.mode.");
        }
        BssOidcSupport support = supportFor(trimToNull(properties.getOidc().getProvider()));
        // AF-05: un proveedor incompleto aborta el arranque, no el primer token.
        support.validateConfiguration();
        return support;
    }

    private BssIdentityMode validate(BssIdentityMode mode) {
        if (mode == BssIdentityMode.LOCAL) {
            return mode;
        }
        if (supports.isEmpty()) {
            throw new BssConfigurationException(
                    "bss.security.mode=oidc requiere el módulo " + MODULE_HINT
                            + " en el classpath y no se encontró ningún proveedor OIDC disponible. "
                            + "Agregá la dependencia o usá bss.security.mode=local.");
        }

        String provider = trimToNull(properties.getOidc().getProvider());
        if (provider == null) {
            throw new BssConfigurationException(
                    "bss.security.oidc.provider es obligatorio en modo oidc. Disponibles: " + providers() + ".");
        }
        if (supportFor(provider) == null) {
            throw new BssConfigurationException(
                    "Proveedor OIDC desconocido: '" + provider + "'. Disponibles: " + providers() + ".");
        }
        return mode;
    }

    private BssOidcSupport supportFor(String provider) {
        if (provider == null) {
            return null;
        }
        return supports.stream()
                .filter(support -> provider.equalsIgnoreCase(support.provider()))
                .findFirst()
                .orElse(null);
    }

    private String providers() {
        Set<String> names = new LinkedHashSet<>();
        for (BssOidcSupport support : supports) {
            names.add(support.provider());
        }
        return String.join(", ", names);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
