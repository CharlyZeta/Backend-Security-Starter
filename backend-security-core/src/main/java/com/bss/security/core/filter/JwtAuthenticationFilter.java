package com.bss.security.core.filter;

import com.bss.security.core.config.BssCacheProperties;
import com.bss.security.core.exception.JwtValidationException;
import com.bss.security.core.service.JwtTokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Autentica la request a partir del Bearer token.
 *
 * Reglas duras del contrato (FIX-0001):
 * - BR-001: ninguna excepción de autenticación escapa al contenedor.
 * - BR-005: el token se parsea una sola vez por request.
 *
 * Cuando el token es inválido, está expirado o el usuario no existe, el filtro
 * NO lanza: deja la request sin autenticar y sigue la cadena. El
 * {@code AuthenticationEntryPoint} responde 401 con el path real, en lugar del
 * 500 que antes producía la excepción escapando del filtro.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;
    private final BssCacheProperties cacheProperties;

    // Caché in-memory de UserDetails (FEAT-0001 la reemplaza por una acotada con TTL).
    private final Map<String, UserDetails> userCache = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7).trim();
        if (jwt.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            authenticate(jwt, request);
        } catch (JwtValidationException | AuthenticationException ex) {
            // Credencial inválida, expirada, malformada o de un usuario inexistente.
            // Se limpia el contexto y se continúa: la respuesta la arma el EntryPoint.
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(String jwt, HttpServletRequest request) {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            return;
        }

        // Parseo y verificación de firma/expiración en una sola pasada (BR-005).
        Claims claims = jwtTokenService.parseClaims(jwt);
        String username = claims.getSubject();
        if (username == null || username.isBlank()) {
            return;
        }

        // Puede lanzar UsernameNotFoundException (AuthenticationException): usuario inexistente.
        UserDetails userDetails = getUserDetails(username);
        if (!username.equals(userDetails.getUsername())) {
            return;
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private UserDetails getUserDetails(String username) {
        if (cacheProperties.isEnabled()) {
            return userCache.computeIfAbsent(username, userDetailsService::loadUserByUsername);
        }
        return userDetailsService.loadUserByUsername(username);
    }
}
