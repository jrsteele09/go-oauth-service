package auth_test

import (
	"testing"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/users"
	"github.com/stretchr/testify/require"
)

func TestValidator_ValidatePKCE(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid S256", func(t *testing.T) {
		err := v.ValidatePKCE("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", true)
		require.NoError(t, err)
	})

	t.Run("missing both when required", func(t *testing.T) {
		err := v.ValidatePKCE("", "", true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "PKCE required")
	})

	t.Run("missing both when optional", func(t *testing.T) {
		err := v.ValidatePKCE("", "", false)
		require.NoError(t, err)
	})

	t.Run("challenge too short", func(t *testing.T) {
		err := v.ValidatePKCE("tooshort", "S256", false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "length must be between")
	})

	t.Run("invalid method", func(t *testing.T) {
		err := v.ValidatePKCE("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "invalid", false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be 'S256' or 'plain'")
	})
}

func TestValidator_ValidateClientCredentials(t *testing.T) {
	v := auth.NewValidator()

	confidentialClient := &clients.Client{
		ID:     "confidential",
		Secret: "secret123",
		Type:   clients.ClientTypeConfidential,
	}

	publicClient := &clients.Client{
		ID:   "public",
		Type: clients.ClientTypePublic,
	}

	t.Run("valid confidential client", func(t *testing.T) {
		err := v.ValidateClientCredentials("confidential", "secret123", confidentialClient)
		require.NoError(t, err)
	})

	t.Run("valid public client", func(t *testing.T) {
		err := v.ValidateClientCredentials("public", "", publicClient)
		require.NoError(t, err)
	})

	t.Run("wrong secret", func(t *testing.T) {
		err := v.ValidateClientCredentials("confidential", "wrong", confidentialClient)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid client secret")
	})

	t.Run("public client with secret", func(t *testing.T) {
		err := v.ValidateClientCredentials("public", "shouldnt-have", publicClient)
		require.Error(t, err)
		require.Contains(t, err.Error(), "public clients must not provide client_secret")
	})
}

func TestValidator_ValidateAccessToken(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid JWT", func(t *testing.T) {
		err := v.ValidateAccessToken("eyJhbGc.eyJzdWI.signature")
		require.NoError(t, err)
	})

	t.Run("empty token", func(t *testing.T) {
		err := v.ValidateAccessToken("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "access token is required")
	})

	t.Run("invalid format", func(t *testing.T) {
		err := v.ValidateAccessToken("not-a-jwt")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be a valid JWT")
	})
}

func TestValidator_ValidateUserCredentials(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid credentials", func(t *testing.T) {
		err := v.ValidateUserCredentials("user@example.com", "password123")
		require.NoError(t, err)
	})

	t.Run("empty email", func(t *testing.T) {
		err := v.ValidateUserCredentials("", "password123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "email is required")
	})

	t.Run("invalid email format", func(t *testing.T) {
		err := v.ValidateUserCredentials("userexample.com", "password123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid email format")
	})

	t.Run("empty password", func(t *testing.T) {
		err := v.ValidateUserCredentials("user@example.com", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "password is required")
	})
}

func TestValidator_ValidateUserState(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid user", func(t *testing.T) {
		user := &users.User{
			ID:       "user-1",
			Verified: true,
			Blocked:  false,
		}
		err := v.ValidateUserState(user)
		require.NoError(t, err)
	})

	t.Run("nil user", func(t *testing.T) {
		err := v.ValidateUserState(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user not found")
	})

	t.Run("blocked user", func(t *testing.T) {
		user := &users.User{
			ID:       "user-1",
			Verified: true,
			Blocked:  true,
		}
		err := v.ValidateUserState(user)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user account is blocked")
	})

	t.Run("unverified user", func(t *testing.T) {
		user := &users.User{
			ID:       "user-1",
			Verified: false,
			Blocked:  false,
		}
		err := v.ValidateUserState(user)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user account is not verified")
	})
}

func TestValidator_ValidateAuthorizationCodeGrant(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid with code verifier", func(t *testing.T) {
		params := oauth2.TokenRequest{
			Code:         "valid-code",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		err := v.ValidateAuthorizationCodeGrant(params)
		require.NoError(t, err)
	})

	t.Run("missing code", func(t *testing.T) {
		params := oauth2.TokenRequest{
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		err := v.ValidateAuthorizationCodeGrant(params)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authorization code is required")
	})

	t.Run("code verifier too short", func(t *testing.T) {
		params := oauth2.TokenRequest{
			Code:         "valid-code",
			CodeVerifier: "tooshort",
		}
		err := v.ValidateAuthorizationCodeGrant(params)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be between 43 and 128 characters")
	})
}

func TestValidator_ValidateRefreshTokenGrant(t *testing.T) {
	v := auth.NewValidator()

	t.Run("valid refresh token", func(t *testing.T) {
		params := oauth2.TokenRequest{
			RefreshToken: "valid-refresh-token-12345",
		}
		err := v.ValidateRefreshTokenGrant(params)
		require.NoError(t, err)
	})

	t.Run("missing refresh token", func(t *testing.T) {
		params := oauth2.TokenRequest{}
		err := v.ValidateRefreshTokenGrant(params)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refresh_token is required")
	})
}

func TestValidateScope(t *testing.T) {
	t.Run("valid single scope", func(t *testing.T) {
		err := auth.ValidateScope("openid")
		require.NoError(t, err)
	})

	t.Run("valid multiple scopes", func(t *testing.T) {
		err := auth.ValidateScope("openid profile email")
		require.NoError(t, err)
	})

	t.Run("empty scope", func(t *testing.T) {
		err := auth.ValidateScope("")
		require.NoError(t, err)
	})

	t.Run("scope with newline", func(t *testing.T) {
		err := auth.ValidateScope("openid\nprofile")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid characters")
	})
}

func TestValidateRedirectURI(t *testing.T) {
	t.Run("valid https URI", func(t *testing.T) {
		err := auth.ValidateRedirectURI("https://example.com/callback")
		require.NoError(t, err)
	})

	t.Run("valid http URI", func(t *testing.T) {
		err := auth.ValidateRedirectURI("http://localhost:3000/callback")
		require.NoError(t, err)
	})

	t.Run("empty URI", func(t *testing.T) {
		err := auth.ValidateRedirectURI("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "redirect_uri is required")
	})

	t.Run("invalid scheme", func(t *testing.T) {
		err := auth.ValidateRedirectURI("ftp://example.com/callback")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must use http or https")
	})

	t.Run("URI with fragment", func(t *testing.T) {
		err := auth.ValidateRedirectURI("https://example.com/callback#fragment")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not contain fragments")
	})
}

func TestValidateState(t *testing.T) {
	t.Run("valid state", func(t *testing.T) {
		err := auth.ValidateState("random-state-12345")
		require.NoError(t, err)
	})

	t.Run("empty state", func(t *testing.T) {
		err := auth.ValidateState("")
		require.NoError(t, err)
	})

	t.Run("state too short", func(t *testing.T) {
		err := auth.ValidateState("short")
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least 8 characters")
	})
}

func TestTenantValidator_ValidateTenantAccess(t *testing.T) {
	t.Run("valid access - matching tenant", func(t *testing.T) {
		tv := auth.NewTenantValidator("tenant-1")
		client := &clients.Client{
			ID:       "client-1",
			TenantID: "tenant-1",
		}
		user := &users.User{
			ID:        "user-1",
			TenantIDs: []string{"tenant-1"},
		}
		err := tv.ValidateTenantAccess(client, user, "")
		require.NoError(t, err)
	})

	t.Run("client not authorized for tenant", func(t *testing.T) {
		tv := auth.NewTenantValidator("tenant-1")
		client := &clients.Client{
			ID:       "client-1",
			TenantID: "tenant-2",
		}
		user := &users.User{
			ID:        "user-1",
			TenantIDs: []string{"tenant-1"},
		}
		err := tv.ValidateTenantAccess(client, user, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "client not authorized")
	})

	t.Run("user not authorized for tenant", func(t *testing.T) {
		tv := auth.NewTenantValidator("tenant-1")
		client := &clients.Client{
			ID:       "client-1",
			TenantID: "tenant-1",
		}
		user := &users.User{
			ID:        "user-1",
			TenantIDs: []string{"tenant-2"},
		}
		err := tv.ValidateTenantAccess(client, user, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "user not authorized")
	})
}
