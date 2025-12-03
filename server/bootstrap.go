package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/users"
)

const (
	// System tenant and client configuration
	SystemTenantIdPrefix      = "master-system-tenant"
	SystemClientID            = "admin-dashboard"
	SystemClientName          = "Admin Dashboard"
	DefaultSuperAdminUsername = "admin"

	// Public self-service client for tenant registration
	PublicClientID   = "oauth-client"
	PublicClientName = "OAuth Public Client"
)

// BootstrapSystem is an alias for InitialiseSystem for better naming consistency
func (s *Server) BootstrapSystem(ctx context.Context) (generatedPassword string, err error) {
	return s.InitialiseSystem(ctx)
}

// InitialiseSystem creates the system tenant, admin client, super admin user, and public OAuth client.
// This implements proper OAuth2 PKCE flow for all authentication.
// Returns the generated password on first creation (empty string if already exists)
func (s *Server) InitialiseSystem(ctx context.Context) (generatedPassword string, err error) {
	log.Printf("🔧 Bootstrap: Checking system configuration...")

	baseURL := s.config.GetBaseURL()

	// Step 1: Create or get system tenant
	systemTenant, err := s.initialiseSystemTenant(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to bootstrap system tenant: %w", err)
	}

	// Step 2: Create or get admin dashboard client (public client with PKCE)
	adminClient, err := s.createAdminClient(ctx, systemTenant.ID)
	if err != nil {
		return "", fmt.Errorf("failed to bootstrap admin client: %w", err)
	}

	// Step 2b: Create or get public OAuth client for general use
	publicClient, err := s.createPublicOAuthClient(ctx, systemTenant.ID)
	if err != nil {
		return "", fmt.Errorf("failed to bootstrap public OAuth client: %w", err)
	}

	// Step 3: Create or get super admin user
	superAdminEmail := generateEmailFromBaseURL(DefaultSuperAdminUsername, baseURL)
	generatedPassword, err = s.bootstrapSuperAdmin(ctx, systemTenant.ID, superAdminEmail)
	if err != nil {
		return "", fmt.Errorf("failed to bootstrap super admin: %w", err)
	}

	if generatedPassword != "" {
		log.Printf("✅ Bootstrap complete: System initialized")
		log.Printf("")
		log.Printf("📋 System Configuration:")
		log.Printf("   Base URL:    %s", baseURL)
		log.Printf("   Tenant ID:   %s", systemTenant.ID)
		log.Printf("   Issuer:      %s", systemTenant.Config.Issuer)
		log.Printf("")
		log.Printf("👤 Super Admin Credentials:")
		log.Printf("   Email:       %s", superAdminEmail)
		log.Printf("   Password:    %s", generatedPassword)
		log.Printf("   ⚠️  SAVE THIS PASSWORD - it will not be displayed again!")
		log.Printf("   You will be required to change this password on first login.")
		log.Printf("")
		log.Printf("🔐 OAuth2 Clients Configured:")
		log.Printf("")
		log.Printf("   1️⃣  Admin Dashboard (%s)", adminClient.ID)
		log.Printf("       Authorization: %s/oauth2/authorize", baseURL)
		log.Printf("       Token:         %s/oauth2/token", baseURL)
		log.Printf("       Flow:          PKCE (public client)")
		log.Printf("       Redirect URI:  %s/admin/callback", baseURL)
		log.Printf("")
		log.Printf("   2️⃣  Public OAuth Client (%s)", publicClient.ID)
		log.Printf("       Authorization: %s/oauth2/authorize", baseURL)
		log.Printf("       Token:         %s/oauth2/token", baseURL)
		log.Printf("       Flow:          PKCE (public client)")
		log.Printf("       Scopes:        openid, profile, email, offline_access")
		log.Printf("       Use this client for general OAuth2 authentication flows")
		log.Printf("")
		log.Printf("🌐 Discovery Endpoint:")
		log.Printf("   %s/.well-known/openid-configuration", baseURL)
	} else {
		log.Printf("✅ Bootstrap: System already configured")
		log.Printf("   Base URL: %s", baseURL)
	}

	return generatedPassword, nil
}

// initialiseSystemTenant creates the system tenant if it doesn't exist
func (s *Server) initialiseSystemTenant(ctx context.Context) (*tenants.Tenant, error) {
	// Generate deterministic tenant ID: system-{first 8 chars of UUID}
	tenantUUID := uuid.New().String()[:8]
	tenantID := fmt.Sprintf("%s-%s", SystemTenantIdPrefix, tenantUUID)

	// Check if a system tenant already exists
	const maxList = 100
	offset := 0
	for {
		tenantsList, err := s.repos.Tenants.List(0, maxList)
		if err != nil {
			return nil, fmt.Errorf("failed to list tenants: %w", err)
		}

		for _, t := range tenantsList.Tenants {
			if strings.HasPrefix(t.ID, fmt.Sprintf("%s-", SystemTenantIdPrefix)) {
				log.Printf("   System tenant already exists: %s", t.ID)
				return t, nil
			}
		}
		offset += maxList
		if tenantsList.Total < offset {
			break
		}
	}

	// Get base URL from config
	baseURL := s.config.GetBaseURL()

	// Create new system tenant
	systemTenant, err := tenants.New(tenantID, "System Tenant", "system.local", tenants.TenantConfig{
		Issuer:             baseURL,
		Audience:           "system",
		AccessTokenExpiry:  15 * time.Minute,
		IDTokenExpiry:      1 * time.Hour,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create system tenant object: %w", err)
	}

	if err := s.repos.Tenants.Upsert(systemTenant); err != nil {
		return nil, fmt.Errorf("failed to create system tenant: %w", err)
	}

	log.Printf("   ✅ Created system tenant: %s", tenantID)
	return systemTenant, nil
}

// createAdminClient creates a public OAuth2 client for the admin dashboard
func (s *Server) createAdminClient(ctx context.Context, tenantID string) (*clients.Client, error) {
	// Check if admin client already exists
	existingClient, err := s.repos.Clients.Get(SystemClientID)
	if err == nil && existingClient != nil {
		log.Printf("   Admin client already exists: %s", SystemClientID)
		return existingClient, nil
	}

	// Get base URL from config
	baseURL := s.config.GetBaseURL()

	// Create public client (PKCE flow, no client secret)
	adminClient := &clients.Client{
		ID:          SystemClientID,
		Secret:      "", // Public client has no secret
		Description: SystemClientName,
		TenantID:    tenantID,
		Type:        clients.ClientTypePublic,
		RedirectURIs: []string{
			baseURL + "/admin/callback",
			"http://localhost:3000/admin/callback", // Dev frontend
			"http://localhost:8080/admin/callback", // Local dev
		},
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"admin",        // Tenant admin access
			"system:admin", // System-level admin
		},
	}

	if err := s.repos.Clients.Upsert(adminClient); err != nil {
		return nil, fmt.Errorf("failed to create admin client: %w", err)
	}

	log.Printf("   ✅ Created admin client: %s (public, PKCE)", SystemClientID)
	return adminClient, nil
}

// createPublicOAuthClient creates a general-purpose public OAuth2 client
// This client can be used by any application for standard OAuth2/OIDC flows
func (s *Server) createPublicOAuthClient(ctx context.Context, tenantID string) (*clients.Client, error) {
	// Check if public client already exists
	existingClient, err := s.repos.Clients.Get(PublicClientID)
	if err == nil && existingClient != nil {
		log.Printf("   Public OAuth client already exists: %s", PublicClientID)
		return existingClient, nil
	}

	// Get base URL from config
	baseURL := s.config.GetBaseURL()

	// Create public client for general OAuth2 use (PKCE flow, no client secret)
	publicClient := &clients.Client{
		ID:          PublicClientID,
		Secret:      "", // Public client has no secret
		Description: PublicClientName,
		TenantID:    tenantID,
		Type:        clients.ClientTypePublic,
		RedirectURIs: []string{
			baseURL + "/callback",
			"http://localhost:3000/callback", // Dev frontend
			"http://localhost:8080/callback", // Local dev
			"http://localhost:8081/callback", // Alternative local dev
		},
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
	}

	if err := s.repos.Clients.Upsert(publicClient); err != nil {
		return nil, fmt.Errorf("failed to create public OAuth client: %w", err)
	}

	log.Printf("   ✅ Created public OAuth client: %s (public, PKCE)", PublicClientID)
	return publicClient, nil
}

// bootstrapSuperAdmin creates the super admin user if none exists
func (s *Server) bootstrapSuperAdmin(ctx context.Context, tenantID string, adminEmail string) (generatedPassword string, err error) {
	// Check if any super admin exists
	existingUsers, err := s.repos.Users.List("", 0, 10)
	if err != nil {
		return "", fmt.Errorf("failed to check for existing users: %w", err)
	}

	for _, user := range existingUsers {
		if user.IsSuperAdmin() {
			log.Printf("   Super admin already exists: %s", user.Email)
			return "", nil
		}
	}

	// Generate a secure random password
	passwordBytes := make([]byte, 16)
	if _, err := rand.Read(passwordBytes); err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}
	generatedPassword = base64.URLEncoding.EncodeToString(passwordBytes)

	// Hash the password
	passwordHash, err := users.HashPassword(generatedPassword)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the super admin user in the system tenant
	admin := &users.User{
		Email:        adminEmail,
		Username:     DefaultSuperAdminUsername,
		PasswordHash: passwordHash,
		FirstName:    "System",
		LastName:     "Administrator",
		SystemRoles:  []users.RoleType{users.RoleSuperAdmin},
		Tenants: []users.TenantMembership{
			{
				TenantID: tenantID,
				Roles:    []users.RoleType{users.RoleTenantAdmin},
				JoinedAt: time.Now(),
			},
		},
		Verified:               true,
		Blocked:                false,
		PasswordChangeRequired: true,
		MFType:                 users.MFNone,
	}

	// Sync tenant IDs
	admin.SyncTenantIDs()

	if err := s.repos.Users.Upsert(admin); err != nil {
		return "", fmt.Errorf("failed to create super admin: %w", err)
	}

	log.Printf("   ✅ Created super admin: %s", admin.Email)
	return generatedPassword, nil
}

// generateEmailFromBaseURL creates an email address from a username and base URL
// Example: ("admin", "https://auth.example.com/path") -> "admin@auth.example.com"
func generateEmailFromBaseURL(user, baseURL string) string {
	domain := strings.ReplaceAll(strings.ReplaceAll(baseURL, "https://", ""), "http://", "")
	domain = strings.SplitN(domain, "/", 2)[0] // Remove any path - safe because SplitN always returns at least 1 element
	domain = strings.SplitN(domain, ":", 2)[0] // Remove port if present
	return fmt.Sprintf("%s@%s", user, domain)
}
