# 🔐 Go OAuth Service

[![Go Report Card](https://goreportcard.com/badge/github.com/jrsteele09/go-oauth-service)](https://goreportcard.com/report/github.com/jrsteele09/go-oauth-service)
[![GoDoc](https://godoc.org/github.com/jrsteele09/go-oauth-service?status.svg)](https://godoc.org/github.com/jrsteele09/go-oauth-service)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **⚠️ Work in Progress**: This project is under active development and is not yet ready.

A multi-tenant **OAuth2** and **OpenID Connect (OIDC)** server implementation written in Go. This library provides the core business logic for OAuth2 authorization flows without HTTP endpoints, allowing you to integrate it with any web framework of your choice.

## Architecture

The service follows a clean, layered architecture with clear separation of concerns:

### Core Components

```mermaid
classDiagram
    class AuthorizationService {
        +Authorize(params, loginRedirect, oauthRedirect)
        +Login(sessionID, email, password, oauthRedirect, mfaRedirect)
        +Token(parameters) TokenResponse
        +IntrospectToken(rawToken, clientID, clientSecret) TokenIntrospection
        +RevokeToken(rawToken, tokenTypeHint, clientID, clientSecret)
        +UserInfo(rawToken) map~string~interface
        +GetJWKS(tenantID) JWKS
        +Logout(accessToken, refreshToken)
    }

    class TokenManager {
        +CreateIDToken(user, tenant, clientID, nonce) string
        +CreateAccessToken(user, tenant, clientID, scope) string
        +CreateRefreshToken(clientID, userID, tenantID, scope) string
        +Introspection(rawToken) TokenIntrospection
        +GenerateTokenResponse(parameters, tokenSpecifics) TokenResponse
        +RevokeAccessToken(rawToken)
        +InvalidateRefreshToken(refreshToken)
        +GetJWKS(tenant) JWKS
    }

    class JWTCreator {
        +CreateIDToken(user, tenant, clientID, nonce, signer) string
        +CreateAccessToken(user, tenant, clientID, scope, signer) string
    }

    class JWTInspector {
        +Introspect(rawToken, signerProvider) TokenIntrospection
        +ParseAndExtractJTI(rawToken, signerProvider) string, time
    }

    class RefreshManager {
        +Create(clientID, userID, tenantID, scope) string
        +Get(token) StoredRefreshToken
        +Delete(token)
        +IsExpired(token, tenantExpiry) bool
    }

    class KeyManager {
        +GenerateRSAKeyPair(keyID, bits) KeyPair
        +CreateSignerFromTenant(tenant) Signer
        +LoadKeyPairFromPEM(keyID, privateKeyPEM, publicKeyPEM) KeyPair
    }

    class Repos {
        <<interface>>
        +Users UserRepo
        +Sessions SessionRepo
        +Clients ClientRepo
        +Tenants TenantRepo
        +RefreshTokens RefreshTokenRepo
    }

    AuthorizationService --> TokenManager : uses
    AuthorizationService --> Repos : depends on
    TokenManager --> JWTCreator : creates tokens
    TokenManager --> JWTInspector : validates tokens
    TokenManager --> RefreshManager : manages refresh tokens
    TokenManager --> KeyManager : signs tokens
    TokenManager --> Repos : queries data
```

### Authorization Code Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthService as AuthorizationService
    participant SessionRepo
    participant UserRepo
    participant TokenMgr as TokenManager

    Client->>AuthService: Authorize(params, loginRedirect, oauthRedirect)
    AuthService->>SessionRepo: Upsert(sessionID, sessionData)
    AuthService->>Client: loginRedirect(sessionID)
    
    Note over Client: User provides credentials
    
    Client->>AuthService: Login(sessionID, email, password, oauthRedirect, mfaRedirect)
    AuthService->>UserRepo: GetByEmail(email)
    UserRepo-->>AuthService: user
    AuthService->>AuthService: CheckPasswordHash(password, user.PasswordHash)
    AuthService->>SessionRepo: UpdateUser(sessionID, email)
    AuthService->>SessionRepo: AssignCodeToSessionID(sessionID, authCode)
    AuthService->>Client: oauthRedirect(redirectURI, responseMode, authCode, state)
    
    Note over Client: Exchange code for tokens
    
    Client->>AuthService: Token(parameters)
    AuthService->>SessionRepo: GetSessionFromAuthCode(code)
    SessionRepo-->>AuthService: sessionData
    AuthService->>TokenMgr: GenerateTokenResponse(parameters, tokenSpecifics)
    TokenMgr->>TokenMgr: CreateIDToken(user, tenant, clientID, nonce)
    TokenMgr->>TokenMgr: CreateAccessToken(user, tenant, clientID, scope)
    TokenMgr->>TokenMgr: CreateRefreshToken(clientID, userID, tenantID, scope)
    TokenMgr-->>AuthService: TokenResponse
    AuthService->>UserRepo: SetLoggedIn(email, true)
    AuthService-->>Client: TokenResponse{access_token, id_token, refresh_token}
```

### Refresh Token Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthService as AuthorizationService
    participant TokenMgr as TokenManager
    participant RefreshMgr as RefreshManager
    participant UserRepo

    Client->>AuthService: Token(parameters{refresh_token})
    AuthService->>TokenMgr: GenerateTokenResponse(parameters, tokenSpecifics)
    TokenMgr->>RefreshMgr: Get(refreshToken)
    RefreshMgr-->>TokenMgr: StoredRefreshToken
    TokenMgr->>RefreshMgr: IsExpired(token, tenantExpiry)
    RefreshMgr-->>TokenMgr: false
    TokenMgr->>UserRepo: GetByID(userID)
    UserRepo-->>TokenMgr: user
    TokenMgr->>TokenMgr: CreateAccessToken(user, tenant, clientID, scope)
    TokenMgr->>TokenMgr: CreateIDToken(user, tenant, clientID, "")
    TokenMgr->>RefreshMgr: Create(clientID, userID, tenantID, scope)
    RefreshMgr-->>TokenMgr: newRefreshToken
    TokenMgr-->>AuthService: TokenResponse
    AuthService-->>Client: TokenResponse{access_token, id_token, refresh_token}
```

### Token Introspection & Revocation

```mermaid
sequenceDiagram
    participant ResourceServer
    participant AuthService as AuthorizationService
    participant TokenMgr as TokenManager
    participant Inspector as JWTInspector
    participant RevocationCache

    Note over ResourceServer: Introspection Flow
    ResourceServer->>AuthService: IntrospectToken(token, clientID, clientSecret)
    AuthService->>AuthService: Validate client credentials
    AuthService->>TokenMgr: Introspection(rawToken)
    TokenMgr->>Inspector: Introspect(rawToken, signerProvider)
    Inspector->>Inspector: Parse and validate JWT
    Inspector->>RevocationCache: IsRevoked(jti)
    RevocationCache-->>Inspector: false
    Inspector-->>TokenMgr: TokenIntrospection{active: true, ...}
    TokenMgr-->>AuthService: TokenIntrospection
    AuthService-->>ResourceServer: TokenIntrospection

    Note over ResourceServer: Revocation Flow
    ResourceServer->>AuthService: RevokeToken(token, "access_token", clientID, clientSecret)
    AuthService->>AuthService: Validate client credentials
    AuthService->>TokenMgr: RevokeAccessToken(rawToken)
    TokenMgr->>Inspector: ParseAndExtractJTI(rawToken, signerProvider)
    Inspector-->>TokenMgr: jti, exp
    TokenMgr->>RevocationCache: Add(jti, exp)
    TokenMgr-->>AuthService: success
    AuthService-->>ResourceServer: success
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

For questions and support, please open an issue on GitHub.

---

**Note**: This library provides the core OAuth2/OIDC logic. You'll need to implement HTTP endpoints, database repositories, and deployment configuration for a complete solution.
