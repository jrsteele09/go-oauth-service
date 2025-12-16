package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/users"
)

const (
	// SystemClientID            = "admin-dashboard"
	// SystemClientName          = "Admin Dashboard"
	DefaultSuperAdminUsername = "admin"
)

// InitialiseSystem creates the system tenant, admin client, super admin user, and public OAuth client.
// This implements proper OAuth2 PKCE flow for all authentication.
// Returns the generated password on first creation (empty string if already exists)
func (s *Server) InitialiseSystem(ctx context.Context, config config.Config) error {
	baseURL := s.config.GetBaseURL()

	// Step 1: Create or get system tenant
	systemTenant, err := s.initialiseSystemTenant(s.config)
	if err != nil {
		return fmt.Errorf("[Server InitialiseSystem] failed to bootstrap system tenant: %w", err)
	}

	// Step 2: Create or get admin dashboard client (public client with PKCE)
	adminClient, err := s.createAdminClient(ctx, config)
	if err != nil {
		return fmt.Errorf("[Server InitialiseSystem] failed to bootstrap admin client: %w", err)
	}

	// Step 3: Create or get super admin user
	superAdminEmail := generateEmailFromBaseURL(config.GetSystemAdminUser(), baseURL)
	generatedPassword, err := s.createSuperAdmin(ctx, systemTenant.ID, superAdminEmail, config.GetSystemAdminPassword())
	if err != nil {
		return fmt.Errorf("[Server InitialiseSystem] failed to bootstrap super admin: %w", err)
	}

	if generatedPassword != "" {
		log.Printf("📋 System Configuration:")
		log.Printf("   Base URL:    %s", baseURL)
		log.Printf("   Tenant ID:   %s", systemTenant.ID)
		log.Printf("   Issuer:      %s", systemTenant.Config.Issuer)
		log.Printf("")
		log.Printf("👤 Super Admin Credentials:")
		log.Printf("   Email:       %s", superAdminEmail)
		log.Printf("   Password:    %s     (⚠️ required to change on first time login)", generatedPassword)
		log.Printf("")
		log.Printf("🔐 OAuth2 Clients Configured:")
		log.Printf("")
		log.Printf("   1️⃣  Admin Dashboard (%s)", adminClient.ID)
		log.Printf("       Authorization: %s/oauth2/authorize", baseURL)
		log.Printf("       Token:         %s/oauth2/token", baseURL)
		log.Printf("       Flow:          PKCE (public client)")
		log.Printf("       Redirect URI:  %s/admin/callback", baseURL)
		log.Printf("")
		log.Printf("🌐 Discovery Endpoint:")
		log.Printf("       %s/.well-known/openid-configuration", baseURL)
		log.Printf("")
	}
	return nil
}

// initialiseSystemTenant creates the system tenant if it doesn't exist
func (s *Server) initialiseSystemTenant(config config.Config) (*tenants.Tenant, error) {
	systemTenantID := config.GetSystemTenantID()

	// Check if a system tenant already exists
	const maxList = 100
	offset := 0
	for {
		tenantsList, err := s.repos.Tenants.List(offset, maxList)
		if err != nil {
			return nil, fmt.Errorf("[server initialiseSystemTenant] failed to list tenants: %w", err)
		}

		for _, t := range tenantsList.Tenants {
			if strings.EqualFold(t.ID, systemTenantID) {
				log.Printf("[server initialiseSystemTenant] System tenant already exists: %s", t.ID)
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

	systemTenant, err := tenants.New(systemTenantID, config.GetSystemTenantName(), config.GetSystemTenantDomain(), tenants.TenantConfig{
		Issuer:             baseURL,
		Audience:           config.GetSystemTenantAudience(),
		AccessTokenExpiry:  15 * time.Minute,
		IDTokenExpiry:      1 * time.Hour,
		RefreshTokenExpiry: 24 * time.Hour,
		LoginURL:           baseURL + "/login",
	})
	if err != nil {
		return nil, fmt.Errorf("[server initialiseSystemTenant] failed to create system tenant object: %w", err)
	}

	if err := s.repos.Tenants.Upsert(systemTenant); err != nil {
		return nil, fmt.Errorf("[server initialiseSystemTenant] failed to create system tenant: %w", err)
	}

	return systemTenant, nil
}

// createAdminClient creates a public OAuth2 client for the admin dashboard
func (s *Server) createAdminClient(_ context.Context, config config.Config) (*clients.Client, error) {
	// Check if admin client already exists
	existingClient, err := s.repos.Clients.Get(config.GetSystemTenantID(), config.GetAdminClientID())
	if err == nil && existingClient != nil {
		log.Printf("[server createAdminClient] Admin client already exists: %s", config.GetAdminClientID())
		return existingClient, nil
	}

	// Get base URL from config
	baseURL := s.config.GetBaseURL()

	// Create public client (PKCE flow, no client secret)
	adminClient := &clients.Client{
		ID:          config.GetAdminClientID(),
		Type:        clients.ClientTypePublic,
		Description: config.GetAdminClientName(),
		Secret:      "", // Public client has no secret
		TenantID:    config.GetSystemTenantID(),

		RedirectURIs: []string{
			baseURL + "/callback",
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

	if err := s.repos.Clients.Upsert(config.GetSystemTenantID(), adminClient); err != nil {
		return nil, fmt.Errorf("[server createAdminClient] failed to create admin client: %w", err)
	}

	return adminClient, nil
}

// createSuperAdmin creates the super admin user if none exists
func (s *Server) createSuperAdmin(_ context.Context, tenantID, adminUserEmail, defaultPassword string) (generatedPassword string, err error) {

	// Check if any super admin exists
	existingUser, err := s.repos.Users.GetByEmail(tenantID, adminUserEmail)
	if err == nil && existingUser != nil && existingUser.IsSuperAdmin() {
		return "", nil
	}

	generatedPassword = defaultPassword

	if generatedPassword == "" {
		// Generate a secure random password
		passwordBytes := make([]byte, 16)
		if _, err := rand.Read(passwordBytes); err != nil {
			return "", fmt.Errorf("[server createSuperAdmin] failed to generate password: %w", err)
		}
		generatedPassword = base64.URLEncoding.EncodeToString(passwordBytes)

	}

	// Hash the password
	passwordHash, err := users.HashPassword(generatedPassword)
	if err != nil {
		return "", fmt.Errorf("[server createSuperAdmin] failed to hash password: %w", err)
	}

	// Create the super adminUser user in the system tenant
	adminUser := &users.User{
		Email:        adminUserEmail,
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

	if err := s.repos.Users.Upsert(tenantID, adminUser); err != nil {
		return "", fmt.Errorf("[server createSuperAdmin] failed to create super admin: %w", err)
	}
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
