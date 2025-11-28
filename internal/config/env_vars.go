package config

import (
	"fmt"
	"os"
)

const (
	portEnvVar   = "PORT"
	appNameVar   = "APP_NAME"
	folderEnvVar = "FOLDER"
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
	return GetEnv(appNameVar, "Go OAuth Server")
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

func GetEnv(envVar, defaultValue string) string {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}
	return value
}
