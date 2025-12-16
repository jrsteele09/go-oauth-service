package config

import (
	"fmt"
	"os"
)

const (
	portEnvVar              = "PORT"
	appNameVar              = "APP_NAME"
	folderEnvVar            = "FOLDER"
	baseURLVar              = "BASE_URL"
	systemTenantIDVar       = "SYSTEM_TENANT_ID"
	systemAdminEmailVar     = "SYSTEM_ADMIN_USER"
	systemAdminPasswordVar  = "SYSTEM_ADMIN_PASSWORD"
	systemTenantDomainVar   = "SYSTEM_TENANT_DOMAIN"
	systemTenantNameVar     = "SYSTEM_TENANT_NAME"
	systemTenantAudienceVar = "SYSTEM_TENANT_AUDIENCE"
	adminClientIDVar        = "ADMIN_CLIENT_ID"
	adminClientNameVar      = "ADMIN_CLIENT_NAME"
)

type EnvVars struct{}

// GetProjectID implements EnvConfig.
func (e EnvVars) GetProjectID() string {
	return GetEnv("PROJECT_ID", "")
}

// GetReCaptchaKey implements EnvConfig.
func (e EnvVars) GetReCaptchaKey() string {
	return GetEnv("RECAPTCHA_KEY", "")
}

var _ EnvConfig = EnvVars{}

func (EnvVars) GetPort() string {
	port := GetEnv(portEnvVar, "8080")
	if port != "" || port[0] != ':' {
		port = fmt.Sprintf(":%s", port)
	}
	return port
}

func (EnvVars) GetAppName() string {
	return GetEnv(appNameVar, "OAuth Server (Name TBD)")
}

func (EnvVars) GetSmtpPassword() string {
	return GetEnv("SMTP_PASSWORD", "")
}

func (EnvVars) GetSmtpAccount() string {
	return GetEnv("SMTP_ACCOUNT", "")
}

func (EnvVars) GetSmtpHost() string {
	return GetEnv("SMTP_HOST", "smtp.gmail.com")
}

func (EnvVars) GetSmtpPort() string {
	return GetEnv("SMTP_PORT", "587")
}

func (EnvVars) GetSmtpRecipient() string {
	return GetEnv("EMAIL_RECIPIENT", "")
}

func (EnvVars) GetDataFolder() string {
	return GetEnv(folderEnvVar, "./data")
}

func (EnvVars) GetEnv() string {
	env := os.Getenv("ENV")
	if env == "" {
		return "DEV"
	}
	return env
}

// GetBaseURL returns the base URL for the OAuth server (e.g., "https://auth.example.com")
// This is used for issuer URLs, redirect URIs, and all OAuth endpoints
func (EnvVars) GetBaseURL() string {
	return GetEnv(baseURLVar, "http://localhost:8080")
}

func GetEnv(envVar, defaultValue string) string {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}
	return value
}

func (EnvVars) GetSystemTenantID() string {
	return GetEnv(systemTenantIDVar, "system-tenant")
}

func (EnvVars) GetSystemAdminUser() string {
	return GetEnv(systemAdminEmailVar, "admin")
}

func (EnvVars) GetSystemAdminPassword() string {
	return GetEnv(systemAdminPasswordVar, "admin")
}

func (e EnvVars) GetSystemTenantDomain() string {
	return GetEnv(systemTenantDomainVar, "system.local")
}

func (e EnvVars) GetSystemTenantName() string {
	return GetEnv(systemTenantNameVar, "System Tenant")
}

func (e EnvVars) GetSystemTenantAudience() string {
	return GetEnv(systemTenantAudienceVar, "system")
}

func (e EnvVars) GetAdminClientID() string {
	return GetEnv(adminClientIDVar, "admin-dashboard")
}

func (e EnvVars) GetAdminClientName() string {
	return GetEnv(adminClientNameVar, "Admin Dashboard")
}
