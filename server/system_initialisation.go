package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jrsteele09/go-auth-server/auth/users"
	"github.com/jrsteele09/go-auth-server/config"
	"github.com/jrsteele09/go-auth-server/tenants"
)

const (
	DefaultSuperAdminUsername = "admin"
)

// InitialiseSystem creates the system tenant and super admin user.
// Returns the generated password on first creation.
func (s *Server) InitialiseSystem(ctx context.Context, config config.Config) error {
	baseURL := s.config.GetBaseURL()

	systemTenant, err := s.initialiseSystemTenant(s.config)
	if err != nil {
		return fmt.Errorf("[Server InitialiseSystem] failed to bootstrap system tenant: %w", err)
	}

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
				loginURL := config.GetBaseURL() + "/auth/login"
				if t.Config.LoginURL != loginURL || t.Domain != "" {
					t.Domain = ""
					t.Config.LoginURL = loginURL
					if err := s.repos.Tenants.Upsert(t); err != nil {
						return nil, fmt.Errorf("[server initialiseSystemTenant] failed to update system tenant: %w", err)
					}
				}
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
	systemTenant, err := tenants.New(systemTenantID, config.GetSystemTenantName(), "", tenants.TenantConfig{
		Issuer:             baseURL,
		Audience:           config.GetSystemTenantAudience(),
		AccessTokenExpiry:  15 * time.Minute,
		IDTokenExpiry:      1 * time.Hour,
		RefreshTokenExpiry: 24 * time.Hour,
		LoginURL:           baseURL + "/auth/login",
	})
	if err != nil {
		return nil, fmt.Errorf("[server initialiseSystemTenant] failed to create system tenant object: %w", err)
	}

	if err := s.repos.Tenants.Upsert(systemTenant); err != nil {
		return nil, fmt.Errorf("[server initialiseSystemTenant] failed to create system tenant: %w", err)
	}

	return systemTenant, nil
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
