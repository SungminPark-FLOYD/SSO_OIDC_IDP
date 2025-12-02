package com.oidc.oauth.api.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthClientService {
    private final OAuthClientRepository repo;
    private final BCryptPasswordEncoder passwordEncoder;

    public RegisteredClient loadClientByClientId(String clientId) {
        OAuthClient result = repo.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not Found Exception: " + clientId));

        return loadClientByResult(result);
    }

    public RegisteredClient findByIdString(String id) {
        Long longId = Long.valueOf(id);
        OAuthClient result  = repo.findById(longId).get();

        return loadClientByResult(result);
    }

    private RegisteredClient loadClientByResult(OAuthClient result) {
        return RegisteredClient.withId(result.getClientId())
                .clientId(result.getClientId())
                .clientSecret(passwordEncoder.encode(result.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(result.getRedirectUri())
                .postLogoutRedirectUri(result.getPostLogoutRedirectUri())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(result.isRequireAuthorizationConsent()).build())
                .build();
    }

    public List<String> getOriginUris() {
        //TODO 구현 필요
        return List.of("http://localhost:40002", "http://localhost:40001");
    }
}
