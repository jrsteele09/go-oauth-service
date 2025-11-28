package config

type Config interface {
	EnvConfig
	CorsConfig
	OAuthConfig
	SecurityConfig
}

type EnvConfig interface {
	GetPort() string
	GetAppName() string
	GetDataFolder() string
	GetSmtpHost() string
	GetSmtpPort() string
	GetSmtpPassword() string
	GetSmtpAccount() string
	GetSmtpRecipient() string
	GetReCaptchaKey() string
	GetProjectID() string
	GetEnv() string
}

type CorsConfig interface {
	GetAllowedOrigins() AllowedOrigins
	GetAllowedMethods() string
	GetAllowedHeaders() string
}

type mainConfig struct {
	EnvVars
	Cors
	OAuth
	Security
}

func New() Config {
	return mainConfig{}
}
