package com.bss.security.core.identity;

/**
 * El IdP no está disponible para resolver claves o validar el token (FEAT-0007 / BR-004).
 *
 * <p>No es una credencial inválida: el token puede ser correcto y el problema estar del lado
 * del proveedor. El filtro lo traduce a <strong>503</strong> para no mentirle al cliente con un
 * 401, y para que el monitoreo muestre una caída del IdP en vez de un pico de credenciales
 * rechazadas. Los proveedores deben lanzarla desde su seam de resolución de claves.
 */
public class BssIdentityUnavailableException extends RuntimeException {

    public BssIdentityUnavailableException(String message) {
        super(message);
    }

    public BssIdentityUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
