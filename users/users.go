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

type User struct {
	ID           string     `json:"id,omitempty"`          // Unique identifier for the user
	Email        string     `json:"email,omitempty"`       // User's email address
	Username     string     `json:"username,omitempty"`    // Unique username
	PasswordHash string     `json:"-"`                     // Hashed version of the user's password - never serialize
	FirstName    string     `json:"first_name,omitempty"`  // First name of the user
	LastName     string     `json:"last_name,omitempty"`   // Last name of the user
	DateJoined   time.Time  `json:"date_joined,omitempty"` // Date and time when the user registered
	LastLogin    time.Time  `json:"last_login,omitempty"`  // Last time the user logged in
	Roles        []string   `json:"roles,omitempty"`       // Roles assigned to the user (e.g., admin, user, moderator)
	TenantIDs    []string   `json:"tenants,omitempty"`     // TenantIDs assigned to the user
	Verified     bool       `json:"verified,omitempty"`    // Verified, has the user verified who they are
	Blocked      bool       `json:"blocked,omitempty"`     // Blocked, has the user been blocked from logging in
	LoggedIn     bool       `json:"loggedIn,omitempty"`    // LoggedIn, Is the user currently loggedIn
	MFType       MFAuthType `json:"mfType,omitempty"`      // MFType, Multifactor type
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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
