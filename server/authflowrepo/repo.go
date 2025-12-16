package authflowrepo

import "time"

type AuthFlowState struct {
	TenantID     string
	CodeVerifier string
	Nonce        string
	ReturnURL    string
	CreatedAt    time.Time
}

type Repo interface {
	Upsert(state string, authState *AuthFlowState) error
	Get(state string) (*AuthFlowState, error)
	Delete(state string) error
}
