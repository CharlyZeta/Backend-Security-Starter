package com.bss.security.core.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Adapter to map SecurityUser to Spring Security UserDetails.
 */
public record BssSecurityUserAdapter(SecurityUser securityUser) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return securityUser.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return securityUser.getPassword();
    }

    @Override
    public String getUsername() {
        return securityUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return securityUser.isEnabled();
    }
}
