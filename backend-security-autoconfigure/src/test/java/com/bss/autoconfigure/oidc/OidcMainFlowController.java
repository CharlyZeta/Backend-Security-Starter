package com.bss.autoconfigure.oidc;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint protegido de la app de prueba del Main Flow HTTP de FEAT-0014.
 *
 * <p>Vive en su propio archivo (y no anidado en el test) para que el component scan de la app
 * lo registre una sola vez y el contexto arranque con un mapeo único.
 */
@RestController
class OidcMainFlowController {

    @GetMapping("/api/test")
    public String test() {
        return "Allowed!";
    }
}
