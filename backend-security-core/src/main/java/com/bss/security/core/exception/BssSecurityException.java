package com.bss.security.core.exception;

import lombok.Getter;

@Getter
public abstract class BssSecurityException extends RuntimeException {
    private final String errorCode;

    protected BssSecurityException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    protected BssSecurityException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
