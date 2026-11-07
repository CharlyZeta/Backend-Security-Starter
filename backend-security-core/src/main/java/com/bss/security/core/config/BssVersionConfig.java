package com.bss.security.core.config;

import com.bss.security.core.version.BssVersionInfo;
import com.bss.security.core.version.BssVersionProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Expone las versiones del build como bean, para la API de gestión y OpenAPI. */
@Configuration
public class BssVersionConfig {

    @Bean
    public BssVersionInfo bssVersionInfo() {
        return BssVersionProvider.load();
    }
}
