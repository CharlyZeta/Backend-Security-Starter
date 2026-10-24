package com.bss.security.core.config;

import com.bss.security.core.exception.BssErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Escritura homogénea de las respuestas de seguridad (BR-004).
 * Centraliza el mapper para que 401 y 403 compartan formato y para que
 * `timestamp` salga siempre en ISO-8601 y nunca como array numérico (BR-006).
 */
final class SecurityErrorWriter {

    private SecurityErrorWriter() {
    }

    /**
     * Copia el mapper de la aplicación (respetando su configuración) y fuerza
     * ISO-8601 para las fechas. Nunca se usa un mapper nuevo suelto: eso
     * ignoraría la configuración del consumidor.
     */
    static ObjectMapper configure(ObjectMapper source) {
        ObjectMapper mapper = source != null ? source.copy() : new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    static void write(HttpServletResponse response, ObjectMapper mapper,
                      BssErrorResponse error, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(mapper.writeValueAsString(error));
    }
}
