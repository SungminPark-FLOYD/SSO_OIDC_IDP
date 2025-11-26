package com.oidc.oauth.api.client;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "OAUTH_CLIENT")
public class OAuthClient {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "client_seq_gen")
    @SequenceGenerator(
            name = "client_seq_gen",
            sequenceName = "SEQ_CLIENT",
            allocationSize = 1
    )
    private Long id;

    @Column(nullable = false, unique = true)
    private String clientId;

    @Column(nullable = false)
    private String clientSecret;

    private String clientName;

    private String redirectUri; // 콤마로 여러 URI 구분 가능

    private String scopes; // 예: "openid,profile,email"

    private String authorizedGrantTypes; // 예: "authorization_code,refresh_token"

    private Integer tokenTtl = 3600;

    @Column(name = "CREATED_AT")
    private LocalDateTime createdAt = LocalDateTime.now();

}
