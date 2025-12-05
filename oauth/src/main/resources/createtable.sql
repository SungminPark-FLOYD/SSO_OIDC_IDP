create table OAUTH_CLIENT
(
    ID                       NUMBER        not null
        primary key,
    CLIENT_ID                VARCHAR2(100) not null
        unique,
    CLIENT_SECRET            VARCHAR2(200) not null,
    CLIENT_NAME              VARCHAR2(200),
    REDIRECT_URI             VARCHAR2(1000),
    SCOPES                   VARCHAR2(500),
    AUTHORIZED_GRANT_TYPES   VARCHAR2(500),
    TOKEN_TTL                NUMBER       default 3600,
    CREATED_AT               TIMESTAMP(6) default SYSTIMESTAMP,
    IS_REQUIRE_AUTH_CONSENT  NUMBER,
    POST_LOGOUT_REDIRECT_URI VARCHAR2(4000)
)
    /

create trigger TRG_CLIENT_ID
    before insert
    on OAUTH_CLIENT
    for each row
    when (NEW.ID IS NULL)
BEGIN
    SELECT SEQ_CLIENT.NEXTVAL INTO :NEW.ID FROM DUAL;
END;
/


create table USERS
(
    USER_ID    NUMBER        not null
        primary key,
    LOGIN_ID   VARCHAR2(100) not null
        unique,
    PASSWORD   VARCHAR2(200) not null,
    NAME       VARCHAR2(100),
    EMAIL      VARCHAR2(200),
    ENABLED    NUMBER(1)    default 1,
    CREATED_AT TIMESTAMP(6) default SYSTIMESTAMP,
    ROLE       VARCHAR2(25)
)
    /

create trigger TRG_USERS_ID
    before insert
    on USERS
    for each row
    when (NEW.USER_ID IS NULL)
BEGIN
    SELECT SEQ_USERS.NEXTVAL INTO :NEW.USER_ID FROM DUAL;
END;
/


-- 1. 사용자 추가 (ID: user1, PW: password)
-- BCrypt Hash: $2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRkgVKhW/yCkIhd8/..
INSERT INTO USERS (USER_ID, LOGIN_ID, PASSWORD, NAME, ROLE, ENABLED, CREATED_AT)
VALUES (1, 'user1', '{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG', '홍길동', 'USER', 1, SYSDATE);

select * from USERS;
select * from OAUTH_CLIENT;
-- 2. 클라이언트 추가 (ID: oidc-client, Secret: secret)
-- Redirect URI는 로컬 테스트용으로 설정함
INSERT INTO OAUTH_CLIENT (
    ID,
    CLIENT_ID,
    CLIENT_SECRET,
    CLIENT_NAME,
    REDIRECT_URI,
    SCOPES,
    AUTHORIZED_GRANT_TYPES,
    TOKEN_TTL,
    IS_REQUIRE_AUTH_CONSENT,
    CREATED_AT
) VALUES (
             2,
             'test-client',
             '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
             'test',
             'http://localhost:40001/callback',
             'openid,profile,email',
             'authorization_code,refresh_token',
             3600,
             1,
             SYSDATE
         );

ALTER TABLE oauth_client
    ADD post_logout_redirect_uri VARCHAR2(4000);
