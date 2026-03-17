package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/alandtse/poc-cell-oauth/pkg/models"
)

const (
	// OpaqueTokenTTL - 14 days as per real STS
	OpaqueTokenTTL = 14 * 24 * time.Hour // 1209600 seconds

	// JWTTokenTTL for exchanged tokens
	JWTTokenTTL = 14 * 24 * time.Hour

	// PrefixLength is the length of the random prefix used for routing
	PrefixLength = 13

	// SuffixLength is the length of the random suffix
	SuffixLength = 21
)

// TokenStore defines the interface for token persistence (Cassandra/DynamoDB).
type TokenStore interface {
	Store(token *models.OpaqueToken) error
	Get(tokenStr string) (*models.OpaqueToken, error)
	Revoke(tokenStr string) error
	RevokeByClient(clientID string) error
}

// ApplicationStore defines the interface for credential/application registry.
type ApplicationStore interface {
	Get(clientID string) (*models.Application, error)
	Authenticate(clientID, clientSecret string) (*models.Application, error)
}

// PrefixStore maps token prefixes to cell IDs for routing.
type PrefixStore interface {
	Set(prefix, cellID string)
	Get(prefix string) (string, bool)
}

// TokenService handles the complete opaque token lifecycle.
type TokenService struct {
	cellID      string
	env         string // "D", "H", "P" (dev, homolog, prod)
	site        string // "dev", "hom", "prd"
	source      string // "INT", "EXT"
	issuer      string
	jwtSecret   []byte // HMAC key for JWT signing (mock; in prod use RSA)
	tokenStore  TokenStore
	appStore    ApplicationStore
	prefixStore PrefixStore
}

func NewTokenService(
	cellID, env, site, source, issuer string,
	jwtSecret []byte,
	tokenStore TokenStore,
	appStore ApplicationStore,
	prefixStore PrefixStore,
) *TokenService {
	return &TokenService{
		cellID:      cellID,
		env:         env,
		site:        site,
		source:      source,
		issuer:      issuer,
		jwtSecret:   jwtSecret,
		tokenStore:  tokenStore,
		appStore:    appStore,
		prefixStore: prefixStore,
	}
}

// generateRandomString creates a URL-safe random string of the given byte length.
func generateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:byteLen], nil
}

// generateOpaqueToken creates a token in the format: {prefix}.{client_id}.{suffix}
// The prefix is used by the Compass Router to route to the correct cell/shard.
func (s *TokenService) generateOpaqueToken(clientID string) (token, prefix string, err error) {
	pfx, err := generateRandomString(PrefixLength)
	if err != nil {
		return "", "", err
	}

	suffix, err := generateRandomString(SuffixLength)
	if err != nil {
		return "", "", err
	}

	fullToken := fmt.Sprintf("%s.%s.%s", pfx, clientID, suffix)
	return fullToken, pfx, nil
}

// ExtractPrefix extracts the routing prefix from an opaque token.
// Token format: {prefix}.{client_id}.{suffix}
func ExtractPrefix(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid opaque token format: expected prefix.client_id.suffix")
	}
	return parts[0], nil
}

// ExtractClientID extracts the client_id from an opaque token.
func ExtractClientID(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid opaque token format")
	}
	return parts[1], nil
}

// ============================================================
// 1. GERAÇÃO DE TOKEN OPACO (client_credentials)
// ============================================================

// IssueOpaqueToken generates an opaque token for a client with token_opaco=true.
// This is the same request as JWT issuance, but the response differs.
func (s *TokenService) IssueOpaqueToken(clientID, clientSecret string) (*models.OpaqueTokenResponse, error) {
	app, err := s.appStore.Authenticate(clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !app.TokenOpaco {
		return nil, fmt.Errorf("application is not configured for opaque tokens (token_opaco=false)")
	}

	token, prefix, err := s.generateOpaqueToken(clientID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	opaqueToken := &models.OpaqueToken{
		Token:     token,
		Prefix:    prefix,
		ClientID:  clientID,
		CellID:    s.cellID,
		Scope:     strings.Join(app.Scopes, " "),
		ExpiresAt: now.Add(OpaqueTokenTTL),
		CreatedAt: now,
		Active:    true,
		Source:    s.source,
		Env:       s.env,
		Flow:      "CC",
	}

	// Store token in database (Cassandra)
	if err := s.tokenStore.Store(opaqueToken); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// Register prefix -> cell mapping for routing
	s.prefixStore.Set(prefix, s.cellID)

	return &models.OpaqueTokenResponse{
		Sub:         clientID,
		Iss:         s.issuer,
		AccessToken: token,
		ExpiresIn:   fmt.Sprintf("%d", int(OpaqueTokenTTL.Seconds())),
		Source:      s.source,
		Env:         s.env,
		Site:        s.site,
		Flow:        "CC",
	}, nil
}

// IssueJWTToken generates a standard JWT token for clients WITHOUT token_opaco.
func (s *TokenService) IssueJWTToken(clientID, clientSecret string) (*models.JWTTokenResponse, error) {
	app, err := s.appStore.Authenticate(clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if app.TokenOpaco {
		return nil, fmt.Errorf("application is configured for opaque tokens, use opaque flow")
	}

	scope := strings.Join(app.Scopes, " ")
	now := time.Now()
	exp := now.Add(JWTTokenTTL)

	accessJWT, err := s.signJWT(clientID, scope, now, exp)
	if err != nil {
		return nil, err
	}

	refreshJWT, err := s.signJWT(clientID, scope, now, exp.Add(24*time.Hour))
	if err != nil {
		return nil, err
	}

	return &models.JWTTokenResponse{
		AccessToken:  accessJWT,
		TokenType:    "Bearer",
		ExpiresIn:    int(JWTTokenTTL.Seconds()),
		RefreshToken: refreshJWT,
		Scope:        scope,
	}, nil
}

// ============================================================
// 2. TOKEN EXCHANGE (opaque → JWT)
//    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
// ============================================================

// ExchangeToken takes an opaque subject_token and returns a JWT.
// This is used when an API (resource provider) receives an opaque token
// and needs to exchange it at the STS for a JWT to access the resource.
func (s *TokenService) ExchangeToken(clientID, clientSecret, subjectToken, resource string) (*models.TokenExchangeResponse, error) {
	// Authenticate the calling client
	_, err := s.appStore.Authenticate(clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Validate the opaque subject_token
	opaqueToken, err := s.tokenStore.Get(subjectToken)
	if err != nil {
		return nil, fmt.Errorf("invalid subject_token: %w", err)
	}

	if !opaqueToken.Active {
		return nil, fmt.Errorf("subject_token has been revoked")
	}

	if time.Now().After(opaqueToken.ExpiresAt) {
		return nil, fmt.Errorf("subject_token has expired")
	}

	// Generate JWT from opaque token data
	now := time.Now()
	exp := now.Add(JWTTokenTTL)

	accessJWT, err := s.signJWT(opaqueToken.ClientID, opaqueToken.Scope, now, exp)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	refreshJWT, err := s.signJWT(opaqueToken.ClientID, opaqueToken.Scope, now, exp.Add(24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh JWT: %w", err)
	}

	return &models.TokenExchangeResponse{
		AccessToken:     accessJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(JWTTokenTTL.Seconds()),
		RefreshToken:    refreshJWT,
		Scope:           opaqueToken.Scope,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Active:          true,
	}, nil
}

// ============================================================
// 3. REVOGAÇÃO DE TOKEN
//    grant_type=token (custom) — revoke from database
// ============================================================

// RevokeToken deactivates an opaque token in the database.
// Returns nil on success. The HTTP handler returns 200 OK empty body.
func (s *TokenService) RevokeToken(clientID, clientSecret, tokenStr string) error {
	// Authenticate
	_, err := s.appStore.Authenticate(clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Revoke — even if token not found, return success (idempotent)
	_ = s.tokenStore.Revoke(tokenStr)
	return nil
}

// ============================================================
// 4. INTROSPECÇÃO DE TOKEN (token_info / tokeninfo)
//    Validates if an opaque token is active
// ============================================================

// Introspect validates a token and returns its metadata (RFC 7662).
func (s *TokenService) Introspect(tokenStr string) (*models.IntrospectionResponse, error) {
	t, err := s.tokenStore.Get(tokenStr)
	if err != nil || !t.Active || time.Now().After(t.ExpiresAt) {
		return &models.IntrospectionResponse{Active: false}, nil
	}

	return &models.IntrospectionResponse{
		Active:    true,
		Scope:     t.Scope,
		ClientID:  t.ClientID,
		TokenType: "opaque",
		Exp:       t.ExpiresAt.Unix(),
		Iat:       t.CreatedAt.Unix(),
		Sub:       t.ClientID,
		CellID:    t.CellID,
		Source:    t.Source,
		Env:       t.Env,
		Flow:      t.Flow,
	}, nil
}

// ============================================================
// JWT SIGNING (mock — in production use RSA keys from HSM)
// ============================================================

func (s *TokenService) signJWT(sub, scope string, iat, exp time.Time) (string, error) {
	// Header
	header := base64Encode([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// Payload
	payload := fmt.Sprintf(
		`{"sub":"%s","iss":"%s","iat":%d,"exp":%d,"scope":"%s","cell_id":"%s","env":"%s","source":"%s"}`,
		sub, s.issuer, iat.Unix(), exp.Unix(), scope, s.cellID, s.env, s.source,
	)
	payloadB64 := base64Encode([]byte(payload))

	// Signature (HMAC-SHA256)
	signingInput := header + "." + payloadB64
	mac := hmac.New(sha256.New, s.jwtSecret)
	mac.Write([]byte(signingInput))
	signature := base64Encode(mac.Sum(nil))

	return signingInput + "." + signature, nil
}

func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
