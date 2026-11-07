package com.bss.security.core.version;

/**
 * Versiones del artefacto y de su stack, resueltas en build time desde el parent pom.
 *
 * <p>Una sola fuente: {@code <revision>} y las propiedades de versión de {@code pom.xml}.
 * El archivo {@code bss-version.properties} lo genera {@code maven-resources-plugin} y
 * {@code VersionConsistencyTest} verifica que no derive respecto del runtime y del README.
 */
public record BssVersionInfo(
        String version,
        String springBoot,
        String springSecurity,
        String jjwt,
        String java) {

    public static final String UNKNOWN = "unknown";
}
