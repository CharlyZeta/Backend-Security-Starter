# Stack — Backend Security Starter (BSS)

## 1. Tecnología

- **Lenguaje:** Java 21 (LTS). `pom.xml` fija `<bss.java.version>21</bss.java.version>`.
- **Framework:** Spring Boot 3.3.4 · Spring Security 6.3.3.
- **Build:** Maven multi-módulo (`core` → `autoconfigure` → `starter`; `sample` al final).
- **JWT:** JJWT 0.12.6 (HS256).
- **Docs API:** springdoc-openapi 2.6.0 (Swagger UI).
- **Tests:** JUnit 5 + AssertJ + Mockito + `spring-security-test` + MockMvc.

## 2. Entorno de ejecución

Requisitos: **JDK 21**, **Maven 3.9+** y **Node.js 18+** (`scripts/sync-versions.mjs` y las
utilidades de `mcp/`). No hay `mvnw` todavía (es parte de FEAT-0005).

```bash
# Verificar antes de correr el Loop
java -version    # debe decir 21
mvn -v           # debe usar el JDK 21 como runtime
```

En esta máquina el JDK 21 no es el `JAVA_HOME` por defecto, así que las rutas concretas viven en
`.sdd/sdd-env.ps1` (script local, fuera de git). El Loop lo hace `dot-source` antes de validar:

```powershell
. .\.sdd\sdd-env.ps1
```

`stack.md` no contiene rutas de máquina a propósito: es el contrato de entorno que viaja con el
repo; las rutas absolutas son configuración local.

## 3. Versión del proyecto

**Fuente única:** `pom.xml` → `<revision>`, más las propiedades `bss.java.version`,
`spring-security.version` y `jjwt.version`. `java.version` **deriva** de `bss.java.version` y
`spring-boot.version` es un **espejo manual** de la versión del parent (un test lo compara contra
el runtime). Los módulos heredan la versión y nadie la repite.

Se propaga sola a:

| Destino | Mecanismo |
|---|---|
| Artefactos Maven | `${revision}` + `flatten-maven-plugin` (resuelve el literal al instalar/publicar) |
| Código (`/api/bss/config`, OpenAPI) | `bss-version.properties` filtrado por `maven-resources-plugin` → `BssVersionInfo` |
| Badges y snippets del README | `node scripts/sync-versions.mjs` |
| Deriva silenciosa | `VersionConsistencyTest` (falla el build) |

**Para cambiar la versión:** editá `<revision>`, actualizá la primera entrada del `CHANGELOG.md`
(lo exige `VersionConsistencyTest`) y corré `node scripts/sync-versions.mjs` (reescribe badges y
snippets del README). Después, `mvn verify` y tag. También se puede sobreescribir en el build:
`mvn -Drevision=0.2.0 install`.

## 4. Comandos canónicos

| Propósito | Comando |
|---|---|
| Build + tests | `mvn -B -ntp test` |
| Build completo | `mvn -B -ntp verify` |
| Instalar módulos (necesario para el sample) | `mvn -B -ntp -DskipTests install` |
| Correr el ejemplo | `mvn -B -ntp -DskipTests install` y luego `mvn -B -ntp -pl backend-security-sample spring-boot:run` (puerto **8081**) |
| Un test puntual | `mvn -B -ntp test -Dtest=JwtTokenServiceTest` |

**Trampa conocida:** `mvn spring-boot:run -pl backend-security-sample` **falla en un clon limpio** porque los módulos no están instalados. Siempre `install` primero.

## 5. Convenciones de tests (obligatorias para el tester-agent)

- Un test por criterio, con el ID en el nombre: `testBR001_...`, `testAF01_...`, `testAC001_...`.
- `@DisplayName` en formato BDD: `GIVEN ... WHEN ... THEN ...`.
- Tests de contrato HTTP con `MockMvc` **no** alcanzan: el enmascarado por `/error` solo aparece con un contenedor real. Los criterios que dependen del status HTTP final deben probarse con `@SpringBootTest(webEnvironment = RANDOM_PORT)` + `TestRestTemplate`, o con un test del `ErrorPageFilter`.
- Nunca usar `scanBasePackages` en un test que pretenda validar la autoconfiguración: eso enmascara los beans que la autoconfiguración no registra.

## 6. Capas de verificación SDD-GL

Los comandos por defecto de SDD-GL son de Node; en este proyecto se sobreescriben por entorno:

```powershell
$env:SDD_LOOP_CMD_FUNCTIONAL = 'mvn -B -ntp test'
$env:SDD_LOOP_CMD_STATIC     = 'mvn -B -ntp -DskipTests compile'
$env:SDD_LOOP_CMD_SECURITY   = 'mvn -B -ntp -pl backend-security-core,backend-security-autoconfigure test -Dtest=*Security*,*Identity*,*Oidc* -Dsurefire.failIfNoSpecifiedTests=false'
$env:SDD_LOOP_CMD_ARCH       = 'mvn -B -ntp -q -DskipTests install'
```

La capa `arch` **no** es un chequeo automático de `CONSTITUTION.md`: hoy ejecuta `install` y la
verificación de los invariantes C-01..C-08 es una revisión manual (no hay ArchUnit ni test de
arquitectura).

Atajo: `. .\.sdd\sdd-env.ps1` en la raíz del proyecto.

## 7. Límites arquitectónicos (verificación de capa `arch`)

- `backend-security-core` **no** puede depender de `backend-security-autoconfigure` ni del `starter`.
- `backend-security-autoconfigure` **solo** puede depender de `core`.
- El `sample` puede depender del `starter`, nunca de `core` directamente.
- `core` no puede arrastrar `spring-boot-starter-web` como dependencia transitiva obligatoria (objetivo de **FIX-0003**; hoy todavía la declara y su paso a `optional` está pendiente).
- Ningún módulo publicable puede contener secretos reales (`*.yml` con `secret: "..."`).

## 8. Estado de partida (histórico — línea base medida el 2026-10-23)

Línea base previa a FIX-0001; se conserva como referencia, **no** es el estado actual:

- 17 tests verdes · build 54 s · JDK 21.
- 5 defectos P0 abiertos (ver `INFORME-AUDITORIA-BSS.md`).
- Comportamiento verificado entonces: token inválido → 500, 403 → 401, login del sample → 401, `isEnabled()` ignorado.

**Foto actual (2026-11-07):** 82 métodos `@Test` (60 en core + 22 en autoconfigure, medido con
`mvn -B -ntp verify`); FIX-0001 `RESOLVED` (401/403/500 correctos, `timestamp` ISO-8601, advice
registrado) y FEAT-0013 `RESOLVED` (selector `local|oidc`), por lo que los dos
primeros comportamientos de la lista quedaron corregidos. Siguen abiertos FIX-0002 (`isEnabled()`)
y FIX-0003 (login del sample).
