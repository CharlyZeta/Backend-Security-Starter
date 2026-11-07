# CONSTITUTION — Backend Security Starter (BSS)

Invariantes de arquitectura y de seguridad que **todo** contrato debe respetar.
La capa `arch` del Loop verifica contra este archivo; un contrato que lo contradiga no se aprueba.

Versión: 1.1 · 2026-11-07 · aplica a `main` a partir de `b811b39`.

---

## C-01 · El core no depende de la nube

`backend-security-core` no puede declarar dependencias de proveedores de identidad
(MSAL4J, `azure-identity`, AWS SDK, Key Vault). Toda integración con un IdP vive en un módulo
opcional propio (`backend-security-entra`, `backend-security-oidc`, …) que depende del core,
nunca al revés.

**Verificación:** el `pom.xml` de `core` no menciona `com.microsoft.azure`, `msal4j` ni SDKs cloud.

## C-02 · No se reimplementa criptografía

La validación de firma, el parseo JWS/JWE y la obtención de claves se delegan en librerías
probadas (Nimbus JOSE + JWT / `spring-security-oauth2-jose`, JJWT). BSS aporta configuración,
validadores de claims, mapeo de authorities y política. Escribir un verificador de firma propio
es motivo de rechazo en Gate.

**Verificación:** no hay `Signature.getInstance`, `MessageDigest` sobre material de token ni
parseo manual de base64url en el camino de validación.

## C-03 · Toda caché tiene tope y TTL

Ninguna estructura en memoria crece sin límite. Toda caché nueva declara `maximumSize` y
`expireAfterWrite` (o equivalente) y expone invalidación. Aplica a `UserDetails`, claves JWKS,
tokens MSAL, rate limiting y contadores.

**Verificación:** el tipo de caché es acotado y sus propiedades están enlazadas a configuración.

**Estado (2026-11-07):** incumplido hoy — la caché de `UserDetails` no aplica tope ni TTL efectivos;
lo cubre FEAT-0001.

## C-04 · Ningún secreto, token o credencial en logs ni en errores

Tokens, refresh tokens, `client_secret`, claves privadas y authorization codes no aparecen en
logs, mensajes de error, `toString()`, URLs ni cabeceras de respuesta. Los mensajes de error al
cliente son genéricos y estables.

**Verificación:** grep de los literales de token en mensajes y ausencia de material sensible en
respuestas de error.

**Estado (2026-11-07):** incumplido hoy — `RefreshToken` (`@Data`) expone el token en su
`toString()`; lo cubre FEAT-0002.

## C-05 · Un claim malformado nunca produce una excepción no controlada

Un `roles` que llega como string, un `scp` ausente, un `tid` numérico o un `aud` como objeto
producen rechazo o ausencia de authorities — nunca 500. Todo acceso a claims pasa por una
conversión defensiva que registra un warning.

**Verificación:** tests con claims de tipo inesperado por cada conversor.

## C-06 · Los tests no dependen de un tenant real

Ningún test hace red contra Microsoft, ni requiere credenciales ni tenant. Se usa
`MockOAuth2Server`, WireMock o dobles locales. Un test que necesite internet no entra a `main`.

**Verificación:** el suite corre verde sin red (`mvn -o test` o perfil offline).

## C-07 · Fail-fast en configuración insegura

Configuración incoherente o insegura impide el arranque con un mensaje accionable: secreto
corto, CORS con `*` + credenciales, `tenantId` vacío, skew fuera de rango, certificado vencido,
`client_secret` con `allow-secret=false`, algoritmo no permitido.

**Verificación:** test que arranca con la configuración inválida y espera el fallo.

## C-08 · Los modos de identidad no conviven por accidente

Un despliegue autentica de **una** manera explícita, declarada en `bss.security.mode`:
`local` (tokens propios de BSS, HS256 + refresh propio) u `oidc` (tokens de un IdP externo,
RS/ES/PS con validación asimétrica, `bss.security.oidc.provider` obligatorio y una allowlist de
issuers declarada). En modo `oidc` se desregistran los endpoints de refresh
propios. La convivencia de ambos exige configuración explícita y una regla de selección por
`iss`/`kid`; nunca dos decodificadores compitiendo por la misma request.

**Verificación:** la configuración declara `bss.security.mode`; con `bss.security.mode=oidc` y
`bss.security.oidc.provider=entra`, un token HS256 de BSS se rechaza y, con
`bss.security.mode=local`, se rechaza un token RS256 del IdP.
