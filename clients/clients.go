package clients

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential" // Can keep secrets (server-side apps)
	ClientTypePublic       ClientType = "public"       // Cannot keep secrets (SPAs, mobile apps)
)

type Client struct {
	ID           string     `json:"id"`
	Type         ClientType `json:"type"` // public or confidential
	Description  string     `json:"description"`
	Secret       string     `json:"secret"`
	RedirectURIs []string   `json:"redirectURIs"`
	TenantID     string     `json:"tenantId"`
	Scopes       []string   `json:"scopes"` // Allowed scopes for this client
}

// IsPublic returns true if the client is a public client
func (c *Client) IsPublic() bool {
	return c.Type == ClientTypePublic
}

// HasScope checks if the client has permission for a specific scope
func (c *Client) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ValidateScopes checks if all requested scopes are allowed for this client
func (c *Client) ValidateScopes(requestedScopes string) error {
	if requestedScopes == "" {
		return nil
	}

	// Split space-separated scopes
	scopes := splitScopes(requestedScopes)
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			return ErrInvalidScope
		}
	}
	return nil
}

func splitScopes(scopes string) []string {
	if scopes == "" {
		return []string{}
	}
	result := []string{}
	for _, s := range stringSlice(scopes, " ") {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func stringSlice(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
