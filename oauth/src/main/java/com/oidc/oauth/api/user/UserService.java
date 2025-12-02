package com.oidc.oauth.api.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService implements UserDetailsService {
    private final UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        User user = repo.findByLoginId(loginId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + loginId));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getName())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }

    public Iterable<User> getUsers() {
        return repo.findAll();
    }
}
