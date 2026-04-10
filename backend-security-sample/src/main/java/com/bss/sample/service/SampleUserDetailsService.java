package com.bss.sample.service;

import com.bss.sample.model.UserAccount;
import com.bss.security.core.model.BssSecurityUserAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SampleUserDetailsService implements UserDetailsService {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public SampleUserDetailsService() {
        // Sample User: user@example.com / password
        users.put("user@example.com", UserAccount.builder()
                .email("user@example.com")
                .password("{noop}password") // {noop} for plain text in samples
                .roles(List.of("ROLE_USER"))
                .active(true)
                .build());

        // Sample Admin: admin@example.com / admin123
        users.put("admin@example.com", UserAccount.builder()
                .email("admin@example.com")
                .password("{noop}admin123")
                .roles(List.of("ROLE_USER", "ROLE_BSS_ADMIN"))
                .active(true)
                .build());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return new BssSecurityUserAdapter(user);
    }
}
