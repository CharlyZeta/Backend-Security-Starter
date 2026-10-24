package com.bss.security.core.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

/**
 * Traduce las excepciones de seguridad al schema único {@link BssErrorResponse} (BR-004).
 *
 * Este bean lo registra {@code BssSecurityAutoConfiguration}: sin eso, un consumidor
 * cuyo component scan no alcanza {@code com.bss.security} no tendría el advice y un
 * token inválido terminaba en 500 (defecto original de FIX-0001).
 */
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

    /**
     * Denegación a nivel MVC (métodos con seguridad, validaciones propias del consumidor).
     * La denegación del filtro la resuelve {@code JwtAccessDeniedHandler}.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<BssErrorResponse> handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request) {
        BssErrorResponse error = BssErrorResponse.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message("Access is denied")
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }
}
