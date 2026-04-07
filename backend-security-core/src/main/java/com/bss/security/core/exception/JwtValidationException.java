package com.bss.security.core.exception;

public class JwtValidationException extends BssSecurityException {
    public JwtValidationException(String message) {
        super(message, "JWT_INVALID");
    }

    public JwtValidationException(String message, Throwable cause) {
        super(message, "JWT_INVALID", cause);
    }
}
