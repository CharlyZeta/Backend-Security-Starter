package com.bss.security.core.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decoder compuesto del núcleo OIDC (FEAT-0014 · BR-001, BR-002, BR-004, AF-01, AF-02).
 *
 * <p>Orden de resolución, deliberadamente <strong>antes</strong> de tocar claves:
 * <ol>
 *   <li>Parsea el token <strong>sin verificar la firma</strong> para leer {@code iss} y el
 *       {@code alg} del header. Es el único uso del contenido no verificado: elegir el
 *       decoder de la allowlist. No se confía en ningún otro claim todavía.</li>
 *   <li>Si {@code iss} está ausente o no pertenece a la allowlist → rechazo y
 *       <strong>no se consulta ningún JWKS</strong> (BR-001, AF-01, AC-004).</li>
 *   <li>Si el {@code alg} no pertenece al conjunto del issuer → rechazo sin claves
 *       (BR-002, AF-02, AC-003, AC-006, AC-007).</li>
 *   <li>Recién entonces delega en el decoder cacheado del issuer, que valida firma,
 *       {@code iss}, {@code aud} y ventana (Main Flow paso 3).</li>
 * </ol>
 *
 * <p>El {@code kid} nunca participa de la selección de issuer ni de algoritmo: se usa
 * únicamente dentro del JWKS de ese issuer al verificar la firma (BR-004).
 *
 * <p>La caché de decoders está acotada por la allowlist de configuración (un decoder por
 * {@code iss} declarado, sin claves de entrada), por lo que no crece con el tráfico (C-03).
 * El estado por request es inmutable.
 */
public class OidcJwtDecoder implements JwtDecoder {

    private final Map<String, OidcIssuer> issuers;
    private final OidcJwtDecoderFactory factory;
    private final OidcJwkSetProvider jwkSetProvider;
    private final Map<String, JwtDecoder> decoders = new ConcurrentHashMap<>();

    /**
     * @param issuers         allowlist de issuers
     * @param jwkSetProvider  resolvedor de claves (seam de FEAT-0007)
     */
    public OidcJwtDecoder(List<OidcIssuer> issuers, OidcJwkSetProvider jwkSetProvider) {
        this(issuers, new OidcJwtDecoderFactory(), jwkSetProvider);
    }

    /**
     * @param issuers         allowlist de issuers
     * @param factory         fábrica de decoders por issuer
     * @param jwkSetProvider  resolvedor de claves (seam de FEAT-0007)
     */
    public OidcJwtDecoder(List<OidcIssuer> issuers, OidcJwtDecoderFactory factory, OidcJwkSetProvider jwkSetProvider) {
        Objects.requireNonNull(factory, "factory cannot be null");
        this.factory = factory;
        this.jwkSetProvider = Objects.requireNonNull(jwkSetProvider, "jwkSetProvider cannot be null");

        Map<String, OidcIssuer> byIssuer = new LinkedHashMap<>();
        if (issuers != null) {
            for (OidcIssuer issuer : issuers) {
                if (issuer != null && issuer.issuer() != null) {
                    byIssuer.put(issuer.issuer(), issuer);
                }
            }
        }
        this.issuers = Collections.unmodifiableMap(byIssuer);
    }

    /**
     * @param properties      configuración del núcleo OIDC
     * @param jwkSetProvider  resolvedor de claves (seam de FEAT-0007)
     */
    public OidcJwtDecoder(OidcProperties properties, OidcJwkSetProvider jwkSetProvider) {
        this(properties == null ? List.of() : properties.getIssuers(), jwkSetProvider);
    }

    /**
     * @param properties      configuración del núcleo OIDC
     * @param factory         fábrica de decoders por issuer
     * @param jwkSetProvider  resolvedor de claves (seam de FEAT-0007)
     */
    public OidcJwtDecoder(OidcProperties properties, OidcJwtDecoderFactory factory, OidcJwkSetProvider jwkSetProvider) {
        this(properties == null ? List.of() : properties.getIssuers(), factory, jwkSetProvider);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        SignedJWT signedJwt = requireSignedJwt(token);
        String issuerName = readIssuer(signedJwt);
        OidcIssuer issuer = issuerName == null ? null : this.issuers.get(issuerName);

        if (issuer == null) {
            // BR-001 / AF-01 / AC-004: allowlist cerrada, sin claves.
            throw new InvalidBearerTokenException("El issuer del token no está en la allowlist configurada");
        }

        String algorithm = readAlgorithm(signedJwt);
        if (algorithm == null || !issuer.algorithms().contains(algorithm)) {
            // BR-002 / AF-02 / AC-003 / AC-006 / AC-007: algoritmo fijado por issuer.
            throw new InvalidBearerTokenException("El algoritmo del token no está permitido para el issuer");
        }

        return decoderFor(issuer).decode(token);
    }

    private JwtDecoder decoderFor(OidcIssuer issuer) {
        // Acotado por la allowlist: como máximo un decoder por issuer declarado (C-03).
        return this.decoders.computeIfAbsent(issuer.issuer(),
                key -> this.factory.decoderFor(issuer, this.jwkSetProvider));
    }

    private static SignedJWT requireSignedJwt(String token) {
        if (token == null || token.isBlank()) {
            throw new BadJwtException("Token JWT ausente");
        }
        JWT parsed;
        try {
            parsed = JWTParser.parse(token);
        } catch (ParseException ex) {
            // Mensaje genérico: nunca se refleja el token ni su contenido (C-04).
            throw new BadJwtException("Token JWT malformado", ex);
        }
        if (parsed instanceof PlainJWT) {
            // AC-006: alg=none no se acepta.
            throw new BadJwtException("Token JWT sin firma no permitido");
        }
        if (!(parsed instanceof SignedJWT signedJwt)) {
            throw new BadJwtException("Token JWT no soportado");
        }
        return signedJwt;
    }

    private static String readIssuer(SignedJWT signedJwt) {
        try {
            String issuer = signedJwt.getJWTClaimsSet().getIssuer();
            return issuer == null ? null : issuer.trim();
        } catch (ParseException ex) {
            throw new BadJwtException("Token JWT con claims ilegibles", ex);
        }
    }

    private static String readAlgorithm(SignedJWT signedJwt) {
        if (signedJwt.getHeader().getAlgorithm() == null) {
            return null;
        }
        return signedJwt.getHeader().getAlgorithm().getName();
    }
}
