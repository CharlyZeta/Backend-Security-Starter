package com.bss.security.core.exception;

/**
 * Error de request mal formada en la capa de seguridad (FIX-0001 / AC-005).
 *
 * Existe porque {@link BssSecurityException} es abstracta: el advice la mapea a 400,
 * así que un body sin {@code refreshToken} deja de producir un 500 por NPE.
 */
public class BssBadRequestException extends BssSecurityException {

    public static final String CODE = "BSS_BAD_REQUEST";

    public BssBadRequestException(String message) {
        super(message, CODE);
    }
}
