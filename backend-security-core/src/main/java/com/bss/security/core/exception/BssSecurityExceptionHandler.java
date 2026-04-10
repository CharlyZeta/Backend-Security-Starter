package com.bss.security.core.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class BssSecurityExceptionHandler {

    @ExceptionHandler(JwtValidationException.class)
    public ResponseEntity<BssErrorResponse> handleJwtValidationException(JwtValidationException ex, HttpServletRequest request) {
        BssErrorResponse error = BssErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(BssSecurityException.class)
    public ResponseEntity<BssErrorResponse> handleBssSecurityException(BssSecurityException ex, HttpServletRequest request) {
        BssErrorResponse error = BssErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Security Error")
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }
}
