package models

import "time"

// Application represents a registered OAuth 2.0 credential/application.
// Matches the credential format from the STS portal.
type Application struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	OrganizationID  string   `json:"organizationId"`
	Phone           *string  `json:"phone"`
	Email           string   `json:"email"`
	CreatedBy       string   `json:"createdBy"`
	ManagedBy       []string `json:"managedBy"`
	CreatedOn       int64    `json:"createdOn"`
	Enabled         bool     `json:"enabled"`
	Image           *string  `json:"image"`
	State           string   `json:"state"` // "approved", "pending", "rejected"
	UsarRevoke      bool     `json:"usar_revoke"`
	TokenOpaco      bool     `json:"token_opaco"`      // if true, credential generates opaque tokens
	ReqCertificado  bool     `json:"req_certificado"`
	AplicaRSA       bool     `json:"aplica_rsa"`
	Provider        string   `json:"provider"` // "AD", "LDAP", etc.
	ReqFlowID       bool     `json:"req_flowId"`
	ClientSecret    string   `json:"client_secret"`
	Scopes          []string `json:"scopes"`
}

// OpaqueToken represents an opaque token stored in the database (Cassandra/DynamoDB).
// Format: {prefix}.{client_id}.{random_suffix}
// The prefix is used by the router (Compass) to determine which cell/shard to route to.
type OpaqueToken struct {
	Token     string    `json:"token"`      // full token: prefix.client_id.suffix
	Prefix    string    `json:"prefix"`     // token prefix for routing
	ClientID  string    `json:"client_id"`
	CellID    string    `json:"cell_id"`    // cell that issued this token
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
	Source    string    `json:"source"` // "INT", "EXT"
	Env       string    `json:"env"`    // "D", "H", "P"
	Flow      string    `json:"flow"`   // "CC" (client_credentials)
}

// OpaqueTokenResponse is the response body when generating an opaque token.
// Matches the real STS response format.
type OpaqueTokenResponse struct {
	Sub         string `json:"sub"`
	Iss         string `json:"iss"`
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
	Source      string `json:"source"`
	Env         string `json:"env"`
	Site        string `json:"site"`
	Flow        string `json:"flow"`
}

// TokenExchangeResponse is returned when exchanging an opaque token for a JWT.
// grant_type=urn:ietf:params:oauth:grant-type:token-exchange
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
	Active          bool   `json:"active"`
}

// IntrospectionResponse follows RFC 7662.
// For opaque tokens, returns if token is active + metadata.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	CellID    string `json:"cell_id,omitempty"`
	Source    string `json:"source,omitempty"`
	Env       string `json:"env,omitempty"`
	Flow      string `json:"flow,omitempty"`
}

// JWTTokenResponse is the standard JWT token response (non-opaque flow).
type JWTTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// CellInfo represents a cell (shard) in the cluster.
type CellInfo struct {
	ID          string    `json:"id"`
	Address     string    `json:"address"`
	Healthy     bool      `json:"healthy"`
	CurrentLoad float64   `json:"current_load"` // 0.0 to 1.0
	MaxCapacity int       `json:"max_capacity"` // max TPS
	LastCheck   time.Time `json:"last_check"`
}

// CellHealthResponse is returned by each cell's health endpoint.
type CellHealthResponse struct {
	CellID      string  `json:"cell_id"`
	Status      string  `json:"status"` // "healthy", "degraded", "unhealthy"
	CurrentLoad float64 `json:"current_load"`
	Uptime      int64   `json:"uptime_seconds"`
}
