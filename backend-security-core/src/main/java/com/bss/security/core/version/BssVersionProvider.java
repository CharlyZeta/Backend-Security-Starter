package com.bss.security.core.version;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Lee {@code bss-version.properties} (filtrado por Maven) del classpath.
 *
 * <p>Si el recurso no está —por ejemplo, en un test que corre sin procesar recursos— devuelve
 * {@link BssVersionInfo#UNKNOWN} en lugar de fallar: la versión es información, no un invariante
 * de seguridad.
 */
public final class BssVersionProvider {

    private static final String RESOURCE = "bss-version.properties";

    private BssVersionProvider() {
    }

    public static BssVersionInfo load() {
        Properties properties = new Properties();
        try (InputStream stream = BssVersionProvider.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (stream != null) {
                properties.load(stream);
            }
        } catch (IOException ignored) {
            // Se degrada a UNKNOWN: no vale abortar el arranque por esto.
        }

        return new BssVersionInfo(
                properties.getProperty("bss.version", BssVersionInfo.UNKNOWN),
                properties.getProperty("bss.spring-boot.version", BssVersionInfo.UNKNOWN),
                properties.getProperty("bss.spring-security.version", BssVersionInfo.UNKNOWN),
                properties.getProperty("bss.jjwt.version", BssVersionInfo.UNKNOWN),
                properties.getProperty("bss.java.version", BssVersionInfo.UNKNOWN));
    }
}
