package com.bss.security.core.exception;

/**
 * Configuración de seguridad incoherente o insegura detectada al arrancar (C-07).
 *
 * <p>Extiende {@link RuntimeException} y no {@link BssSecurityException} porque no es un
 * error de request: no se mapea a un status HTTP, aborta el arranque del contexto.
 */
public class BssConfigurationException extends RuntimeException {

    public BssConfigurationException(String message) {
        super(message);
    }
}
