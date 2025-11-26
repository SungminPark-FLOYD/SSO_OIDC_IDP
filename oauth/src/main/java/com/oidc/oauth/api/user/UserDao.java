package com.oidc.oauth.api.user;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserDao {
    private final JdbcTemplate jdbc;

    public UserDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void saveUser(String name) {
        jdbc.update("INSERT INTO users(name) VALUES(?)", name);
    }

    public List<String> findAll() {
        List<String> names = jdbc.queryForList(
                "SELECT name FROM users", String.class
        );
        return names;
    }
}
