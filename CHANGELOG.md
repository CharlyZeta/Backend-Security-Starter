# Changelog - Backend Security Starter (BSS)

All notable changes to this project will be documented in this file.

## [Unreleased]

### 🚀 Added
- **Selector de modo de identidad (`local` | `oidc`) — FEAT-0013:** nueva propiedad
  `bss.security.mode` (validada en el arranque, sin inferencia), `bss.security.oidc.provider`, el
  seam `BssOidcSupport`, `BssConfigurationException` y el registro condicional de los endpoints de
  refresh propios (desactivados en modo `oidc`).
- **Fuente única de versión:** `${revision}` + `flatten-maven-plugin`, el recurso filtrado
  `bss-version.properties`, `BssVersionInfo`/`BssVersionProvider` y `VersionConsistencyTest` como
  guardián del build; `/api/bss/config` y el documento OpenAPI exponen la versión del build.
- **Constitución versionada:** `CONSTITUTION.md` v1.1 con la corrección de C-08
  (`bss.security.mode` + provider) y notas de estado de implementación para C-03/C-04.
- **Núcleo OIDC genérico — FEAT-0014:** allowlist de issuers (`bss.security.oidc.issuers`), validación
  multi-algoritmo (RS256/384/512, ES256/384, PS256) con el algoritmo **fijado por issuer**, `aud` y
  ventana con skew por issuer (default 60 s, máximo 300 s), `exp` obligatorio, y rechazo del `iss`
  desconocido **antes** de resolver claves. Seam `OidcJwkSetProvider` para la resolución de claves
  (su implementación de producción llega con el contrato de JWKS).
- **Desafío `WWW-Authenticate` (RFC 6750):** el entry point emite `Bearer` sin credenciales y
  `Bearer error="invalid_token"` cuando el token presentado no valida.
- **IdP no disponible → 503:** `BssIdentityUnavailableException` permite distinguir una caída del
  proveedor de una credencial inválida (401) y devuelve `Retry-After`.

### 🛠 Changed
- **Versionado del proyecto:** la versión sale de `<revision>` (sobreescribible con
  `mvn -Drevision=...`); badges y snippets del README se generan con
  `node scripts/sync-versions.mjs`.
- **Documentación:** el README documenta los modos de identidad, los prerrequisitos mínimos, la
  Management API simulada y los pasos de ejecución del sample en clon limpio; la caché queda
  marcada como experimental hasta FEAT-0001.

### 🐛 Fixed
- **Contrato HTTP de seguridad — FIX-0001:** token inválido/expirado/desconocido devuelve 401 con
  el path real (ya no 500), el 403 sigue siendo 403, body vacío de refresh devuelve 400, `/error`
  queda fuera de la autenticación, `BssSecurityExceptionHandler` se registra desde la
  autoconfiguración y el token se parsea una sola vez por request.
- **Timestamps ISO-8601:** las respuestas de error de seguridad serializan `timestamp` como string
  ISO-8601 y no como array numérico (BR-006).

## [1.0.0] - 2026-04-05

### 🚀 Added
- **Multi-Module Architecture:** Split into `core`, `autoconfigure`, and `starter` for maximum modularity.
- **Java 21 Native Support:** Optimized for **Virtual Threads** (Project Loom) in the security filter chain.
- **JWT Stateless Security:** Robust implementation using JJWT 0.12.6.
- **Refresh Token System:** 
    - Database-agnostic interface (`RefreshTokenRepository`).
    - **Token Rotation** logic for enhanced security.
    - Default `InMemoryRefreshTokenRepository` for rapid prototyping.
- **Security Baseline:** Deny-all by default (401 Unauthorized) policy.
- **Resilience:** 60-second **Leeway Time** for clock skew synchronization.
- **Management API:** Protected endpoints (`/api/bss/config`) for real-time security dashboard integration.
- **Interactive Documentation:** Automatic **Swagger UI / OpenAPI 3** integration with Bearer Auth support.
- **Professional TDD Suite:** 100% coverage of core security flows (Auth, Refresh, Roles, and Deny-all).

### 🛠 Technical Specs
- **Spring Boot:** 3.3.4
- **Spring Security:** 6.3.3
- **JDK:** 21
- **Auth Pattern:** Bearer JWT + UUID Refresh Token.

---
*Authored by Gerardo Maidana (@CharlyZeta)*
