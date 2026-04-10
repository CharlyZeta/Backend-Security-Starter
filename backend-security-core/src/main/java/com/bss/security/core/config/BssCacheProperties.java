package com.bss.security.core.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "bss.security.cache")
public class BssCacheProperties {
    private boolean enabled = false;
    private long timeToLiveSeconds = 600; // 10 minutes
    private int maxSize = 1000;
    private long cleanupIntervalMs = 3600000; // 1 hour
}
