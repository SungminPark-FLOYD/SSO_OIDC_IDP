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
import java.util.UUID;

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
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(result.getClientId())
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(result.getRedirectUri())
                .postLogoutRedirectUri(result.getPostLogoutRedirectUri())
                .scope(OidcScopes.OPENID)   // OpenID Connect
                .scope(OidcScopes.PROFILE)  // 프로필 정보
                .scope("message.read")      // 메시지 읽기 권한
                .scope("message.write")     // 메시지 쓰기 권한
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(result.isRequireAuthorizationConsent()).build())
                .build();
    }

    public List<String> getOriginUris() {
        //TODO 구현 필요
        return List.of("http://localhost:40002", "http://localhost:40001");
    }

    public RegisteredClient test() {
        // 테스트용 클라이언트 등록
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // 클라이언트 ID: 클라이언트 애플리케이션 식별자
                .clientId("messaging-client")
                // 클라이언트 Secret: 클라이언트 애플리케이션 비밀번호
                .clientSecret(passwordEncoder.encode("secret"))
                // 클라이언트 인증 방법: HTTP Basic 인증
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 허용할 권한 부여 방식: Authorization Code
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 허용할 권한 부여 방식: Refresh Token
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 인증 성공 후 리다이렉트될 URI
                .redirectUri("http://localhost:40001/callback")
                // 클라이언트가 요청할 수 있는 스코프(권한 범위)
                .scope(OidcScopes.OPENID)  // OpenID Connect
                .scope(OidcScopes.PROFILE)  // 프로필 정보
                .scope("message.read")  // 메시지 읽기 권한
                .scope("message.write")  // 메시지 쓰기 권한
                // 클라이언트 설정: PKCE 필수 여부 등
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return registeredClient;
    }
}
