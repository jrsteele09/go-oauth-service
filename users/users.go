package users

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

type MFAuthType string

const (
	MFNone          MFAuthType = "none"
	MFAuthenticator MFAuthType = "authenticator"
	MFEmail         MFAuthType = "email"
	MFTSms          MFAuthType = "sms"
)

// RoleType represents a user role either at system or tenant level
type RoleType string

const (
	// System-level roles
	RoleSuperAdmin    RoleType = "super_admin"    // Can manage all tenants and system configuration
	RoleSystemAuditor RoleType = "system_auditor" // Can view all tenant data for auditing

	// Tenant-level roles
	RoleTenantAdmin  RoleType = "tenant_admin"  // Can manage users, clients, and settings within a tenant
	RoleTenantUser   RoleType = "tenant_user"   // Regular user within a tenant
	RoleTenantViewer RoleType = "tenant_viewer" // Read-only access within a tenant
)

// TenantMembership represents a user's membership and roles within a specific tenant
type TenantMembership struct {
	TenantID string     `json:"tenant_id"`
	Roles    []RoleType `json:"roles"`
	JoinedAt time.Time  `json:"joined_at"`
}

type User struct {
	ID           string    `json:"id,omitempty"`          // Unique identifier for the user
	Email        string    `json:"email,omitempty"`       // User's email address
	Username     string    `json:"username,omitempty"`    // Unique username
	PasswordHash string    `json:"-"`                     // Hashed version of the user's password - never serialize
	FirstName    string    `json:"first_name,omitempty"`  // First name of the user
	LastName     string    `json:"last_name,omitempty"`   // Last name of the user
	DateJoined   time.Time `json:"date_joined,omitempty"` // Date and time when the user registered
	LastLogin    time.Time `json:"last_login,omitempty"`  // Last time the user logged in

	// Role and tenant membership
	SystemRoles []RoleType         `json:"system_roles,omitempty"` // System-wide roles (super_admin, system_auditor)
	Tenants     []TenantMembership `json:"tenants,omitempty"`      // Per-tenant roles and membership
	TenantIDs   []string           `json:"tenant_ids,omitempty"`   // Quick lookup of tenant IDs (derived from Tenants)

	Verified               bool       `json:"verified,omitempty"`                 // Verified, has the user verified who they are
	Blocked                bool       `json:"blocked,omitempty"`                  // Blocked, has the user been blocked from logging in
	LoggedIn               bool       `json:"loggedIn,omitempty"`                 // LoggedIn, Is the user currently loggedIn
	PasswordChangeRequired bool       `json:"password_change_required,omitempty"` // PasswordChangeRequired, forces password reset on next login
	MFType                 MFAuthType `json:"mfType,omitempty"`                   // MFType, Multifactor type
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CheckPasswordHash is a method that checks a password against the user's hash
func (u *User) CheckPasswordHash(password, hash string) bool {
	return CheckPasswordHash(password, hash)
}

func (u *User) HasTenant(tenantID string) bool {
	if tenantID == "" {
		return true
	}
	for _, t := range u.TenantIDs {
		if tenantID == t {
			return true
		}
	}
	return false
}

func (u *User) MFAAuth() bool {
	return u.MFType != "" && u.MFType != MFNone
}

// IsSuperAdmin returns true if the user has super admin privileges
func (u *User) IsSuperAdmin() bool {
	for _, role := range u.SystemRoles {
		if role == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// IsSystemAuditor returns true if the user has system auditor privileges
func (u *User) IsSystemAuditor() bool {
	for _, role := range u.SystemRoles {
		if role == RoleSystemAuditor {
			return true
		}
	}
	return false
}

// HasSystemRole checks if the user has a specific system-level role
func (u *User) HasSystemRole(role RoleType) bool {
	for _, r := range u.SystemRoles {
		if r == role {
			return true
		}
	}
	return false
}

// GetTenantMembership returns the user's membership for a specific tenant
func (u *User) GetTenantMembership(tenantID string) *TenantMembership {
	for i := range u.Tenants {
		if u.Tenants[i].TenantID == tenantID {
			return &u.Tenants[i]
		}
	}
	return nil
}

// GetRolesForTenant returns the user's roles within a specific tenant
func (u *User) GetRolesForTenant(tenantID string) []RoleType {
	membership := u.GetTenantMembership(tenantID)
	if membership != nil {
		return membership.Roles
	}
	return nil
}

// HasTenantRole checks if the user has a specific role within a tenant
func (u *User) HasTenantRole(tenantID string, role RoleType) bool {
	roles := u.GetRolesForTenant(tenantID)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsAdminOfTenant returns true if the user is an admin of the specified tenant
func (u *User) IsAdminOfTenant(tenantID string) bool {
	return u.HasTenantRole(tenantID, RoleTenantAdmin)
}

// CanManageTenant returns true if the user can manage the specified tenant
// Super admins can manage any tenant, or the user must be a tenant admin
func (u *User) CanManageTenant(tenantID string) bool {
	// Super admins can manage any tenant
	if u.IsSuperAdmin() {
		return true
	}
	// User must be admin of that specific tenant
	return u.IsAdminOfTenant(tenantID)
}

// SyncTenantIDs updates the TenantIDs slice from the Tenants memberships
// This should be called after modifying the Tenants slice
func (u *User) SyncTenantIDs() {
	u.TenantIDs = make([]string, len(u.Tenants))
	for i, tm := range u.Tenants {
		u.TenantIDs[i] = tm.TenantID
	}
}
