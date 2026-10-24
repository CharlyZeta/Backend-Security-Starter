package com.bss.security.core.config;

import com.bss.security.core.exception.BssErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Responde 403 con el schema estándar cuando el usuario está autenticado
 * pero no tiene el permiso requerido (BR-004).
 *
 * Antes de existir este handler, Spring Security delegaba en
 * {@code AccessDeniedHandlerImpl}, que hace {@code sendError(403)}: eso
 * disparaba el despacho a {@code /error}, que al estar protegido convertía
 * el 403 en 401. Escribir la respuesta directo elimina ese round-trip.
 */
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public JwtAccessDeniedHandler() {
        this(null);
    }

    public JwtAccessDeniedHandler(ObjectMapper objectMapper) {
        this.objectMapper = SecurityErrorWriter.configure(objectMapper);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        BssErrorResponse error = BssErrorResponse.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message("Access is denied")
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();

        SecurityErrorWriter.write(response, objectMapper, error, HttpStatus.FORBIDDEN.value());
    }
}
