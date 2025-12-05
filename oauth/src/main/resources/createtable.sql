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