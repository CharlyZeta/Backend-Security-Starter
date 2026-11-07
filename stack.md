# Stack — Backend Security Starter (BSS)

## 1. Tecnología

- **Lenguaje:** Java 21 (LTS). `pom.xml` fija `<bss.java.version>21</bss.java.version>`.
- **Framework:** Spring Boot 3.3.4 · Spring Security 6.3.3.
- **Build:** Maven multi-módulo (`core` → `autoconfigure` → `starter`; `sample` al final).
- **JWT:** JJWT 0.12.6 (HS256).
- **Docs API:** springdoc-openapi 2.6.0 (Swagger UI).
- **Tests:** JUnit 5 + AssertJ + Mockito + `spring-security-test` + MockMvc.

## 2. Entorno de ejecución

Requisitos: **JDK 21** y **Maven 3.9+**. No hay `mvnw` todavía (es parte de FEAT-0005).

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

**Fuente única:** `pom.xml` → `<revision>` (y las propiedades `java.version`,
`spring-boot.version`, `spring-security.version`, `jjwt.version`). Los módulos heredan la versión
y nadie la repite.

Se propaga sola a:

| Destino | Mecanismo |
|---|---|
| Artefactos Maven | `${revision}` + `flatten-maven-plugin` (resuelve el literal al instalar/publicar) |
| Código (`/api/bss/config`, OpenAPI) | `bss-version.properties` filtrado por `maven-resources-plugin` → `BssVersionInfo` |
| Badges y snippets del README | `node scripts/sync-versions.mjs` |
| Deriva silenciosa | `VersionConsistencyTest` (falla el build) |

**Para cambiar la versión:** editá `<revision>` y corré `node scripts/sync-versions.mjs`. Sin
editar nada más. También se puede sobreescribir en el build: `mvn -Drevision=0.2.0 install`.

## 4. Comandos canónicos

| Propósito | Comando |
|---|---|
| Build + tests | `mvn -B -ntp test` |
| Build completo | `mvn -B -ntp verify` |
| Instalar módulos (necesario para el sample) | `mvn -B -ntp -DskipTests install` |
| Correr el ejemplo | `mvn -B -ntp -pl backend-security-sample spring-boot:run` (puerto **8081**) |
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
$env:SDD_LOOP_CMD_SECURITY   = 'mvn -B -ntp test -Dtest=*Security*'
$env:SDD_LOOP_CMD_ARCH       = 'mvn -B -ntp -q -DskipTests install'
```

Atajo: `. .\.sdd\sdd-env.ps1` en la raíz del proyecto.

## 7. Límites arquitectónicos (verificación de capa `arch`)

- `backend-security-core` **no** puede depender de `backend-security-autoconfigure` ni del `starter`.
- `backend-security-autoconfigure` **solo** puede depender de `core`.
- El `sample` puede depender del `starter`, nunca de `core` directamente.
- `core` no puede arrastrar `spring-boot-starter-web` como dependencia transitiva obligatoria (objetivo de FEAT-0003/FIX-0003).
- Ningún módulo publicable puede contener secretos reales (`*.yml` con `secret: "..."`).

## 8. Estado de partida (línea base medida)

- 17 tests verdes · build 54 s · JDK 21.
- 5 defectos P0 abiertos (ver `INFORME-AUDITORIA-BSS.md`).
- Comportamiento real verificado: token inválido → 500, 403 → 401, login del sample → 401, `isEnabled()` ignorado.
