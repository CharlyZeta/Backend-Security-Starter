package com.bss.security.core.model;

import java.util.Collection;

/**
 * Contract to decouple security from domain.
 * Third parties must implement this interface.
 */
public interface SecurityUser {
    String getUsername();
    String getPassword();
    Collection<String> getRoles();
    boolean isEnabled();
}
