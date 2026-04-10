package com.bss.sample.model;

import com.bss.security.core.model.SecurityUser;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserAccount implements SecurityUser {
    private String email;
    private String password;
    private List<String> roles;
    private boolean active;

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<String> getRoles() {
        return roles;
    }

    @Override
    public boolean isEnabled() {
        return active;
    }
}
