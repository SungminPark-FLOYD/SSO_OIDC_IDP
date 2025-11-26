package com.oidc.oauth.api.user;

import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public void createUser(String name) {

    }

    public void getUSer() {

    }

    public Iterable<User> getUsers() {
        return repo.findAll();
    }
}
