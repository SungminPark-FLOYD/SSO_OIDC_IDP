package com.oidc.oauth.api.user;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(name = "USERS")
@Getter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq_gen")
    @SequenceGenerator(
            name = "user_seq_gen",
            sequenceName = "SEQ_USERS",
            allocationSize = 1
    )
    private Long userId;

    @Column(name = "LOGIN_ID", nullable = false, unique = true)
    private String loginId;

    @Column(nullable = false)
    private String password;

    private String name;

    private String email;

    private String role;

    private boolean enabled = true;

    @Column(name = "CREATED_AT")
    private LocalDateTime createdAt = LocalDateTime.now();
}
