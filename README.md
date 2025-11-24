# 🔐 Go OAuth Service

[![Go Report Card](https://goreportcard.com/badge/github.com/jrsteele09/go-oauth-service)](https://goreportcard.com/report/github.com/jrsteele09/go-oauth-service)
[![GoDoc](https://godoc.org/github.com/jrsteele09/go-oauth-service?status.svg)](https://godoc.org/github.com/jrsteele09/go-oauth-service)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **⚠️ Work in Progress**: This project is under active development and is not yet production-ready. APIs may change without notice.

A flexible, multi-tenant **OAuth2** and **OpenID Connect (OIDC)** server implementation written in Go. This library currently only provides the core business logic for OAuth2 authorization flows without HTTP endpoints, allowing you to integrate it with any web framework of your choice. HTTP endpoints are a future
enhancement.

## TODO List

- [ ] Complete HTTP endpoints + examples
- [ ] Provide Simple storage implementations


## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       HTTP Layer                            │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ /authorize   │  │ /token       │  │ /userinfo    │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                  │                  │             │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│              auth.AuthorizationService                      │
│                                                             │
│  • Authorize()      - Start OAuth2 flow                     │
│  • Login()          - Authenticate user                     │
│  • Token()          - Exchange code/refresh for tokens      │
│  • IntrospectToken()- Validate token                        │
│  • RevokeToken()    - Revoke access/refresh tokens          │
│  • UserInfo()       - Get user profile                      │
│  • GetJWKS()        - Public keys for verification          │
│  • CleanupExpired() - Remove stale data                     │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                   token.Manager                             │
│                                                             │
│  • CreateAccessToken()   - Generate JWT access tokens       │
│  • CreateIDToken()       - Generate OIDC ID tokens          │
│  • CreateRefreshToken()  - Generate refresh tokens          │
│  • IntrospectToken()     - Validate and decode tokens       │
│  • RevokeAccessToken()   - Revoke specific token            │
│  • CleanupExpired()      - Remove expired revocations       │
└───────────────────┬─────────────────────────────────────────┘
                    │
        ┌───────────┴──────────┐
        │                      │
        ▼                      ▼
┌──────────────┐      ┌──────────────────┐
│token.Signer  │      │  Token Storage   │
│              │      │  (TokenRepo)     │
│ • HMACsigner │      │                  │
│ • Asymmetric │      │  • Save revoked  │
│   Signer     │      │  • Check status  │
│   (RSA/ECDSA)│      │  • Cleanup old   │
└──────────────┘      └──────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│              Repository Layer (Interfaces)              │
│                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │
│  │ Users   │  │ Clients │  │ Tenants │  │Sessions │     │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘     │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│            Your Database (PostgreSQL, MySQL, etc.)      │
└─────────────────────────────────────────────────────────┘
```

## Token Flow Diagram

```
┌──────────┐                                         ┌──────────┐
│  Client  │                                         │  Server  │
│   App    │                                         │          │
└────┬─────┘                                         └────┬─────┘
     │                                                    │
     │  1. GET /authorize?client_id=...&redirect_uri=...  │
     ├───────────────────────────────────────────────────>│
     │                                                    │
     │  2. 302 Redirect to login page                     │
     │<───────────────────────────────────────────────────┤
     │                                                    │
     │  3. POST /login (username, password)               │
     ├───────────────────────────────────────────────────>│
     │                                                    │
     │  4. 302 Redirect with authorization code           │
     │<───────────────────────────────────────────────────┤
     │    Location: redirect_uri?code=xyz&state=abc       │
     │                                                    │
     │  5. POST /token (code, client_secret, PKCE)        │
     ├───────────────────────────────────────────────────>│
     │                                                    │
     │  6. Response: access_token, id_token, refresh_token│
     │<───────────────────────────────────────────────────┤
     │                                                    │
     │  7. API Request with Authorization: Bearer <token> │
     ├───────────────────────────────────────────────────>│
     │                                                    │
     │  8. API Response                                   │
     │<───────────────────────────────────────────────────┤
     │                                                    │
     │  9. POST /token (refresh_token)                    │
     ├───────────────────────────────────────────────────>│
     │                                                    │
     │  10. Response: new access_token, new refresh_token │
     │<───────────────────────────────────────────────────┤
     │                                                    │
```

## Installation

```bash
go get github.com/jrsteele09/go-auth-server
```

## Quick Start

### Basic Setup with HMAC Signing

```go
package main

import (
    "time"
    
    "github.com/jrsteele09/go-auth-server/auth"
    "github.com/jrsteele09/go-auth-server/token"
    "github.com/jrsteele09/go-auth-server/users"
    "github.com/jrsteele09/go-auth-server/clients"
    "github.com/jrsteele09/go-auth-server/tenants"
)

func main() {
    // 1. Initialize your repositories (implement these interfaces)
    userRepo := &YourUserRepo{}
    sessionRepo := &YourSessionRepo{}
    clientRepo := &YourClientRepo{}
    tenantRepo := &YourTenantRepo{}
    tokenRepo := &YourTokenRepo{}

    // 2. Create HMAC signer with secret key
    signer := token.NewHMACsigner("your-secret-key-min-32-bytes-long")

    // 3. Create token manager
    tokenManager := token.New(
        tokenRepo,
        signer,
        token.WithAccessTokenTTL(15*time.Minute),
        token.WithIDTokenTTL(1*time.Hour),
        token.WithRefreshTokenTTL(7*24*time.Hour),
    )

    // 4. Create authorization service
    authService, err := auth.NewAuthorizationService(
        auth.Repos{
            Users:    userRepo,
            Sessions: sessionRepo,
            Clients:  clientRepo,
            Tenants:  tenantRepo,
        },
        tokenManager,
    )
    if err != nil {
        panic(err)
    }

    // 5. Use the service in your HTTP handlers
    // See examples below...
}
```

### Advanced Setup with RSA Signing

```go
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
    
    "github.com/jrsteele09/go-auth-server/token"
)

func main() {
    // Load RSA private key
    privateKeyPEM, _ := ioutil.ReadFile("private_key.pem")
    block, _ := pem.Decode(privateKeyPEM)
    privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

    // Load RSA public key
    publicKeyPEM, _ := ioutil.ReadFile("public_key.pem")
    block, _ = pem.Decode(publicKeyPEM)
    publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
    publicKey := publicKeyInterface.(*rsa.PublicKey)

    // Create asymmetric signer
    signer := token.NewAsymmetricSigner(
        privateKey,
        publicKey,
        "RS256",
        "key-id-001",
    )

    // Use with token manager as above...
    tokenManager := token.New(tokenRepo, signer)
}
```

## Usage Examples

### Example 1: Authorization Flow

```go
// HTTP Handler for /authorize endpoint
func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
    params := &auth.AuthorizationParameters{
        ResponseType:        auth.ResponseTypeCode,
        ClientID:            r.URL.Query().Get("client_id"),
        RedirectURI:         r.URL.Query().Get("redirect_uri"),
        Scope:               r.URL.Query().Get("scope"),
        State:               r.URL.Query().Get("state"),
        CodeChallenge:       r.URL.Query().Get("code_challenge"),
        CodeChallengeMethod: auth.ChallengePlain,
        Nonce:               r.URL.Query().Get("nonce"),
    }

    // Validate and start authorization
    sessionID, err := authService.Authorize(r.Context(), params)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Store session ID in cookie and redirect to login
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    })
    
    http.Redirect(w, r, "/login", http.StatusFound)
}
```

### Example 2: User Login

```go
// HTTP Handler for /login endpoint
func HandleLogin(w http.ResponseWriter, r *http.Request) {
    // Get session from cookie
    cookie, _ := r.Cookie("session_id")
    sessionID := cookie.Value

    // Get credentials from form
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // Authenticate user
    redirectFunc := func(redirectURI, responseMode, authCode, state string) {
        // Build redirect URL with code
        redirectURL := fmt.Sprintf("%s?code=%s&state=%s", 
            redirectURI, authCode, state)
        http.Redirect(w, r, redirectURL, http.StatusFound)
    }

    err := authService.Login(
        r.Context(),
        sessionID,
        email,
        password,
        redirectFunc,
    )
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
}
```

### Example 3: Token Exchange

```go
// HTTP Handler for /token endpoint
func HandleToken(w http.ResponseWriter, r *http.Request) {
    grantType := r.FormValue("grant_type")
    
    switch grantType {
    case "authorization_code":
        tokenParams := auth.TokenRequestParameters{
            GrantType:    auth.GrantTypeAuthorizationCode,
            ClientID:     r.FormValue("client_id"),
            ClientSecret: r.FormValue("client_secret"),
            Code:         r.FormValue("code"),
            RedirectURI:  r.FormValue("redirect_uri"),
            CodeVerifier: r.FormValue("code_verifier"),
        }
        
        response, err := authService.Token(r.Context(), &tokenParams)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        
        json.NewEncoder(w).Encode(response)
        
    case "refresh_token":
        tokenParams := auth.TokenRequestParameters{
            GrantType:    auth.GrantTypeRefreshToken,
            ClientID:     r.FormValue("client_id"),
            ClientSecret: r.FormValue("client_secret"),
            RefreshToken: r.FormValue("refresh_token"),
        }
        
        response, err := authService.Token(r.Context(), &tokenParams)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        
        json.NewEncoder(w).Encode(response)
    }
}
```

### Example 4: Token Introspection

```go
// HTTP Handler for /introspect endpoint
func HandleIntrospect(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    clientID := r.FormValue("client_id")
    clientSecret := r.FormValue("client_secret")
    
    result, err := authService.IntrospectToken(
        r.Context(),
        token,
        clientID,
        clientSecret,
    )
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    json.NewEncoder(w).Encode(result)
}
```

### Example 5: UserInfo Endpoint (OIDC)

```go
// HTTP Handler for /userinfo endpoint
func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
    // Extract token from Authorization header
    authHeader := r.Header.Get("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "Missing token", http.StatusUnauthorized)
        return
    }
    
    token := strings.TrimPrefix(authHeader, "Bearer ")
    
    userInfo, err := authService.UserInfo(r.Context(), token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    json.NewEncoder(w).Encode(userInfo)
}
```

### Example 6: Token Revocation

```go
// HTTP Handler for /revoke endpoint
func HandleRevoke(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    tokenTypeHint := r.FormValue("token_type_hint")
    clientID := r.FormValue("client_id")
    clientSecret := r.FormValue("client_secret")
    
    err := authService.RevokeToken(
        r.Context(),
        token,
        tokenTypeHint,
        clientID,
        clientSecret,
    )
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.WriteHeader(http.StatusOK)
}
```

### Example 7: JWKS Endpoint

```go
// HTTP Handler for /.well-known/jwks.json endpoint
func HandleJWKS(w http.ResponseWriter, r *http.Request) {
    jwks := authService.GetJWKS()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jwks)
}
```

## Token Types Explained

### Access Token (JWT)
- **Purpose**: Authorize API requests
- **Lifespan**: Short (15 minutes default)
- **Format**: Signed JWT
- **Claims**: `sub`, `aud`, `iss`, `exp`, `iat`, `jti`, `tenant_id`, `roles`, `scopes`

### ID Token (JWT - OIDC)
- **Purpose**: User identity information
- **Lifespan**: Medium (1 hour default)
- **Format**: Signed JWT
- **Claims**: `sub`, `aud`, `iss`, `exp`, `iat`, `nonce`, `email`, `name`, `tenant_id`

### Refresh Token (Opaque)
- **Purpose**: Get new tokens without re-authentication
- **Lifespan**: Long (7 days default)
- **Format**: Random 256-bit string (not JWT)
- **Storage**: Stored in database with metadata


## Multi-Tenancy

Each tenant gets isolated:
- User namespace
- Client applications
- Token signing keys (optional)
- Custom scopes and roles

```go
// Example: Creating a tenant-specific client
client := &clients.Client{
    ID:           "client-123",
    Secret:       "hashed-secret",
    TenantID:     "tenant-abc",
    RedirectURIs: []string{"https://app.example.com/callback"},
    Type:         clients.ClientTypeConfidential,
    Scopes:       []string{"openid", "profile", "email"},
}
```

## Testing

The library uses the repository pattern with generated fakes for easy testing:

```go
import (
    "testing"
    "github.com/jrsteele09/go-auth-server/auth"
    "github.com/jrsteele09/go-auth-server/users/repofake"
)

func TestAuthorization(t *testing.T) {
    // Use fake repositories
    fakeUserRepo := &repofake.FakeUserRepo{}
    fakeSessionRepo := &repofakes.FakeSessionRepo{}
    // ... configure fakes
    
    authService, _ := auth.NewAuthorizationService(
        auth.Repos{
            Users:    fakeUserRepo,
            Sessions: fakeSessionRepo,
            // ...
        },
        tokenManager,
    )
    
    // Test your flow
    sessionID, err := authService.Authorize(ctx, params)
    // ... assertions
}
```

## Repository Interfaces

You need to implement these interfaces for your storage layer:

```go
// users.UserRepo
type UserRepo interface {
    GetByEmail(ctx context.Context, tenantID, email string) (*User, error)
    GetByID(ctx context.Context, tenantID, userID string) (*User, error)
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
}

// auth.SessionRepo
type SessionRepo interface {
    Save(ctx context.Context, session *SessionData) error
    Get(ctx context.Context, sessionID string) (*SessionData, error)
    Delete(ctx context.Context, sessionID string) error
    DeleteExpired(ctx context.Context, before time.Time) error
}

// clients.Repo
type Repo interface {
    GetByID(ctx context.Context, tenantID, clientID string) (*Client, error)
    Create(ctx context.Context, client *Client) error
    Update(ctx context.Context, client *Client) error
}

// tenants.Repo
type Repo interface {
    GetByID(ctx context.Context, tenantID string) (*Tenant, error)
    Create(ctx context.Context, tenant *Tenant) error
}

// token.TokenRepo
type TokenRepo interface {
    SaveRevokedToken(ctx context.Context, jti string, exp time.Time) error
    IsRevoked(ctx context.Context, jti string) (bool, error)
    DeleteExpired(ctx context.Context, before time.Time) error
}
```

## Configuration Options

### Token Manager Options

```go
tokenManager := token.New(
    tokenRepo,
    signer,
    token.WithAccessTokenTTL(15*time.Minute),
    token.WithIDTokenTTL(1*time.Hour),
    token.WithRefreshTokenTTL(7*24*time.Hour),
    token.WithIssuer("https://auth.example.com"),
)
```

### Authorization Service Options

```go
authService := auth.NewAuthorizationService(
    repos,
    tokenManager,
    auth.WithNowTime(customTimeFunc), // For testing
)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

For questions and support, please open an issue on GitHub.

---

**Note**: This library provides the core OAuth2/OIDC logic. You'll need to implement HTTP endpoints, database repositories, and deployment configuration for a complete solution.
