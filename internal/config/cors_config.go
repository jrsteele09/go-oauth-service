package config

import "strings"

type Cors struct{}

var _ CorsConfig = Cors{}

type AllowedOrigins map[string]struct{}
type nullValue = struct{}

func (a AllowedOrigins) IsAllowedOrigin(origin string) bool {
	_, ok := a[origin]
	return ok
}

func (a AllowedOrigins) String() string {
	var origins []string
	for k := range a {
		origins = append(origins, k)
	}
	return strings.Join(origins, ", ")
}

var allowedOrigins = AllowedOrigins{"tbd.com": nullValue{}}

func (Cors) GetAllowedOrigins() AllowedOrigins {
	return allowedOrigins
}

func (Cors) GetAllowedMethods() string {
	return "GET, POST, PUT, PATCH, DELETE"
}

func (Cors) GetAllowedHeaders() string {
	return "Content-Type, Authorization"
}
