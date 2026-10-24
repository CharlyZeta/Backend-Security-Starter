package com.bss.security.core.config;

import com.bss.security.core.exception.BssErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Responde 401 con el schema estándar cuando falta la autenticación o la
 * credencial presentada no es válida.
 *
 * El mensaje es siempre genérico: nunca se propaga {@code authException.getMessage()}
 * porque puede filtrar detalles internos (BR-007).
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /** Mensaje público y estable: los clientes y los tests dependen de él. */
    public static final String GENERIC_MESSAGE = "Full authentication is required to access this resource";

    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint() {
        this(null);
    }

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = SecurityErrorWriter.configure(objectMapper);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        BssErrorResponse error = BssErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message(GENERIC_MESSAGE)
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();

        SecurityErrorWriter.write(response, objectMapper, error, HttpStatus.UNAUTHORIZED.value());
    }
}
