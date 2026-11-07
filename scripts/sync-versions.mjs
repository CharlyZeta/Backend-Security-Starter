#!/usr/bin/env node
/**
 * Sincroniza los indicadores de versión del proyecto desde una única fuente: pom.xml.
 *
 * Fuente de verdad:
 *   <revision>                  versión del artefacto
 *   <java.version>              JDK objetivo
 *   <spring-boot.version>       espejo de la versión de Spring Boot (guardada por test)
 *   <spring-security.version>   Spring Security
 *   <jjwt.version>              JJWT
 *
 * Qué reescribe:
 *   - README.md: bloque entre <!-- versions:start --> y <!-- versions:end -->, y todos
 *     los <version>…</version> de los snippets de instalación.
 *
 * Uso:  node scripts/sync-versions.mjs          (escribe)
 *       node scripts/sync-versions.mjs --check  (solo verifica; exit 1 si hay drift)
 */
import { readFileSync, writeFileSync } from 'node:fs';

const CHECK = process.argv.includes('--check');

const pom = readFileSync('pom.xml', 'utf8');

function prop(name, fallback) {
  const match = pom.match(new RegExp(`<${name}>([^<]+)</${name}>`));
  return match ? match[1].trim() : fallback;
}

const version = prop('revision', '0.0.0');
const java = prop('bss.java.version', '21');
const boot = prop('spring-boot.version', '?');
const security = prop('spring-security.version', '?');
const jjwt = prop('jjwt.version', '?');

const REPO = 'https://github.com/CharlyZeta/Backend-Security-Starter';

const block = `<!-- versions:start - bloque generado por scripts/sync-versions.mjs desde pom.xml; no editar a mano -->
[![JitPack](https://jitpack.io/v/CharlyZeta/Backend-Security-Starter.svg)](https://jitpack.io/#CharlyZeta/Backend-Security-Starter)
[![Version](https://img.shields.io/badge/version-${version}-blue.svg)](${REPO}/releases)
[![License](https://img.shields.io/github/license/CharlyZeta/Backend-Security-Starter)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/CharlyZeta/Backend-Security-Starter/maven-build.yml?branch=main)](${REPO}/actions)
![Java ${java}](https://img.shields.io/badge/Java-${java}-orange.svg?style=flat&logo=openjdk)
![Spring Boot ${boot}](https://img.shields.io/badge/Spring--Boot-${boot}-brightgreen.svg?style=flat&logo=springboot)
![Spring Security ${security}](https://img.shields.io/badge/Spring--Security-${security}-green.svg?style=flat&logo=springsecurity)
![JJWT ${jjwt}](https://img.shields.io/badge/JJWT-${jjwt}-blue.svg?style=flat&logo=jsonwebtokens)
<!-- versions:end -->`;

const readmePath = 'README.md';
const original = readFileSync(readmePath, 'utf8');

let next = original.replace(
  /<!-- versions:start[\s\S]*?<!-- versions:end -->/m,
  block
);
next = next.replace(/<version>[^<]+<\/version>/g, `<version>${version}</version>`);

const drifted = next !== original;

if (CHECK) {
  if (drifted) {
    console.error('✗ README desalineado respecto de pom.xml. Corré: node scripts/sync-versions.mjs');
    process.exit(1);
  }
  console.log(`✓ Versiones coherentes (${version}, Java ${java}, Boot ${boot}, Security ${security}, JJWT ${jjwt})`);
  process.exit(0);
}

if (!drifted) {
  console.log(`✓ Sin cambios (${version})`);
  process.exit(0);
}

writeFileSync(readmePath, next, 'utf8');
console.log(`✓ README actualizado: ${version}, Java ${java}, Boot ${boot}, Security ${security}, JJWT ${jjwt}`);
