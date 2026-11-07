package com.bss.security.core.identity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro del modo {@code oidc} (FEAT-0013): delega la validación en el {@link BssOidcSupport}
 * del proveedor declarado.
 *
 * <p>Misma política que el filtro local: si el token no es válido no se autentica y la request
 * sigue la cadena, de modo que el {@code AuthenticationEntryPoint} responda 401 con el path real
 * (BR-001 de FIX-0001). El token HS256 propio nunca se intenta validar en este modo, porque el
 * soporte OIDC fija sus algoritmos (BR-006).
 */
public class OidcAuthenticationFilter extends OncePerRequestFilter {

    private final BssOidcSupport support;

    public OidcAuthenticationFilter(BssOidcSupport support) {
        this.support = support;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            if (!token.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                try {
                    Authentication authentication = support.authenticate(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (AuthenticationException ex) {
                    SecurityContextHolder.clearContext();
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
