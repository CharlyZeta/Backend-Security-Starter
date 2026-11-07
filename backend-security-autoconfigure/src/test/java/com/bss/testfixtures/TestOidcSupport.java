package com.bss.testfixtures;

import com.bss.security.core.identity.BssOidcSupport;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

/**
 * Doble de prueba del módulo OIDC para FEAT-0013: implementa el seam real
 * ({@link BssOidcSupport}) con validación RS256 de verdad, para probar los AC del selector
 * end-to-end sin depender de FEAT-0014. Vive fuera de los paquetes de test-apps para no ser
 * alcanzado por component scan.
 */
public class TestOidcSupport implements BssOidcSupport {

    private final KeyPair keyPair;
    private final RSAPublicKey publicKey;

    public TestOidcSupport() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception ex) {
            throw new IllegalStateException("no se pudo generar el par RSA de prueba", ex);
        }
    }

    @Override
    public String provider() {
        return "test";
    }

    @Override
    public Authentication authenticate(String bearerToken) {
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(bearerToken);

            if (!"RS256".equals(jws.getHeader().getAlgorithm())) {
                throw new BadCredentialsException("algoritmo no permitido");
            }

            String subject = jws.getPayload().getSubject();
            return new UsernamePasswordAuthenticationToken(
                    subject, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        } catch (JwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("token OIDC inválido", ex);
        }
    }

    /** Token RS256 válido para el subject indicado. */
    public String validRs256Token(String subject) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }
}
