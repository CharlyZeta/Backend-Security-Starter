package com.bss.security.core.oidc;

import com.nimbusds.jose.jwk.JWKSet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Provider de claves de prueba con contador (FEAT-0014 · AC-004 / AF-01).
 *
 * <p>Devuelve un {@link JWKSet} estático en memoria y registra cuántas veces se pidió, para
 * demostrar que un {@code iss} no declarado se rechaza <strong>antes</strong> de resolver
 * claves. Sin red y sin estado compartido entre tests.
 */
final class CountingJwkSetProvider implements OidcJwkSetProvider {

    private final Map<String, JWKSet> byIssuer;
    private final JWKSet fallback;
    private final AtomicInteger calls = new AtomicInteger();
    private final List<String> requestedIssuers = new ArrayList<>();

    CountingJwkSetProvider(Map<String, JWKSet> byIssuer, JWKSet fallback) {
        this.byIssuer = new LinkedHashMap<>(byIssuer);
        this.fallback = fallback;
    }

    CountingJwkSetProvider(JWKSet jwkSet) {
        this(Map.of(), jwkSet);
    }

    @Override
    public JWKSet jwkSetFor(OidcIssuer issuer) {
        calls.incrementAndGet();
        synchronized (requestedIssuers) {
            requestedIssuers.add(issuer.issuer());
        }
        JWKSet specific = byIssuer.get(issuer.issuer());
        return specific != null ? specific : fallback;
    }

    int calls() {
        return calls.get();
    }

    List<String> requestedIssuers() {
        synchronized (requestedIssuers) {
            return List.copyOf(requestedIssuers);
        }
    }

    void reset() {
        calls.set(0);
        synchronized (requestedIssuers) {
            requestedIssuers.clear();
        }
    }
}
