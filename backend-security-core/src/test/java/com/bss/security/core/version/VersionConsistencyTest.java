package com.bss.security.core.version;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootVersion;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guardián de la fuente única de versión.
 *
 * <p>Falla el build cuando un indicador de versión se desalinea: el recurso filtrado por Maven,
 * las versiones del stack declaradas, los badges del README, los snippets de instalación o la
 * primera entrada del CHANGELOG. Corre en {@code mvn test}, así que también corre en CI.
 */
class VersionConsistencyTest {

    private static final Path REPO_ROOT = Path.of("..");

    @Test
    @DisplayName("La versión del artefacto la inyecta Maven, no un literal en el código")
    void versionIsInjectedByMaven() {
        BssVersionInfo info = BssVersionProvider.load();

        assertThat(info.version()).isNotBlank().isNotEqualTo(BssVersionInfo.UNKNOWN);
        assertThat(info.java()).isEqualTo(System.getProperty("java.specification.version"));
    }

    @Test
    @DisplayName("Las versiones del stack declaradas coinciden con las del runtime")
    void declaredStackVersionsMatchRuntime() {
        BssVersionInfo info = BssVersionProvider.load();

        assertThat(info.springBoot()).isEqualTo(SpringBootVersion.getVersion());
        assertThat(info.springSecurity()).isEqualTo(SpringSecurityCoreVersion.getVersion());
    }

    @Test
    @DisplayName("El README declara la misma versión en el badge y en los snippets")
    void readmeStaysInSync() throws Exception {
        String readme = Files.readString(REPO_ROOT.resolve("README.md"));
        BssVersionInfo info = BssVersionProvider.load();

        assertThat(readme).contains("version-" + info.version() + "-blue");

        Matcher matcher = Pattern.compile("<version>([^<]+)</version>").matcher(readme);
        int snippets = 0;
        while (matcher.find()) {
            snippets++;
            assertThat(matcher.group(1))
                    .as("versión en snippet de instalación")
                    .isEqualTo(info.version());
        }
        assertThat(snippets).as("el README debe declarar la dependencia con versión").isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("El CHANGELOG abre con la versión del proyecto")
    void changelogTopEntryMatches() throws Exception {
        String changelog = Files.readString(REPO_ROOT.resolve("CHANGELOG.md"));
        BssVersionInfo info = BssVersionProvider.load();

        Matcher matcher = Pattern.compile("^## \\[([^\\]]+)\\]", Pattern.MULTILINE).matcher(changelog);
        assertThat(matcher.find()).as("el CHANGELOG debe tener una entrada de versión").isTrue();
        assertThat(matcher.group(1)).isEqualTo(info.version());
    }
}
