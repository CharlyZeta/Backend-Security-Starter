# Changelog - Backend Security Starter (BSS)

All notable changes to this project will be documented in this file.

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
