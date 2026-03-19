package mock

import (
	"fmt"
	"sync"
	"time"

	"github.com/alandtse/poc-cell-oauth/pkg/models"
)

// TokenStore simulates Cassandra with immediate replication across nodes.
// In production this would be backed by Cassandra (3 nodes with replication)
// or DynamoDB Global Tables.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*models.OpaqueToken // key: full token string
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*models.OpaqueToken),
	}
}

func (s *TokenStore) Store(token *models.OpaqueToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *TokenStore) Get(tokenStr string) (*models.OpaqueToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[tokenStr]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	return t, nil
}

func (s *TokenStore) Revoke(tokenStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenStr]
	if !ok {
		return fmt.Errorf("token not found")
	}
	t.Active = false
	return nil
}

func (s *TokenStore) RevokeByClient(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.ClientID == clientID {
			t.Active = false
		}
	}
	return nil
}

func (s *TokenStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, k)
		}
	}
}

// ListAll returns all tokens in the store (for debug/admin endpoints).
func (s *TokenStore) ListAll() []*models.OpaqueToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*models.OpaqueToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		result = append(result, t)
	}
	return result
}

// ListByClient returns all tokens for a specific client_id.
func (s *TokenStore) ListByClient(clientID string) []*models.OpaqueToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.OpaqueToken
	for _, t := range s.tokens {
		if t.ClientID == clientID {
			result = append(result, t)
		}
	}
	return result
}

// Count returns the total number of tokens and active tokens.
func (s *TokenStore) Count() (total int, active int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		total++
		if t.Active && time.Now().Before(t.ExpiresAt) {
			active++
		}
	}
	return
}

// ApplicationStore simulates the credential/application registry.
// In production this would be DynamoDB or the Portal de Credenciais backend.
type ApplicationStore struct {
	mu   sync.RWMutex
	apps map[string]*models.Application // key: client_id (== Application.ID)
}

func NewApplicationStore() *ApplicationStore {
	return &ApplicationStore{
		apps: make(map[string]*models.Application),
	}
}

func (s *ApplicationStore) Register(app *models.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[app.ID] = app
	return nil
}

func (s *ApplicationStore) Get(clientID string) (*models.Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[clientID]
	if !ok {
		return nil, fmt.Errorf("application not found: %s", clientID)
	}
	return app, nil
}

func (s *ApplicationStore) Authenticate(clientID, clientSecret string) (*models.Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[clientID]
	if !ok {
		return nil, fmt.Errorf("application not found")
	}
	if !app.Enabled {
		return nil, fmt.Errorf("application is disabled")
	}
	if app.State != "approved" {
		return nil, fmt.Errorf("application is not approved (state: %s)", app.State)
	}
	if app.ClientSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}
	return app, nil
}

// TenantCellMapping maps organization IDs (tenants) to cell IDs.
// Simulates DynamoDB mapping table used by the router.
type TenantCellMapping struct {
	mu      sync.RWMutex
	mapping map[string]string // organization_id -> cell_id
}

func NewTenantCellMapping() *TenantCellMapping {
	return &TenantCellMapping{
		mapping: make(map[string]string),
	}
}

func (m *TenantCellMapping) Set(tenantID, cellID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mapping[tenantID] = cellID
}

func (m *TenantCellMapping) Get(tenantID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cellID, ok := m.mapping[tenantID]
	return cellID, ok
}

func (m *TenantCellMapping) Delete(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mapping, tenantID)
}

func (m *TenantCellMapping) GetTenantsByCell(cellID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var tenants []string
	for tid, cid := range m.mapping {
		if cid == cellID {
			tenants = append(tenants, tid)
		}
	}
	return tenants
}

func (m *TenantCellMapping) ReassignCell(fromCellID, toCellID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tid, cid := range m.mapping {
		if cid == fromCellID {
			m.mapping[tid] = toCellID
		}
	}
}

// PrefixCellMapping maps token prefixes to cell IDs.
// This is used by the Compass Router to know which cell owns a token prefix.
type PrefixCellMapping struct {
	mu      sync.RWMutex
	mapping map[string]string // prefix -> cell_id
}

func NewPrefixCellMapping() *PrefixCellMapping {
	return &PrefixCellMapping{
		mapping: make(map[string]string),
	}
}

func (m *PrefixCellMapping) Set(prefix, cellID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mapping[prefix] = cellID
}

func (m *PrefixCellMapping) Get(prefix string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cellID, ok := m.mapping[prefix]
	return cellID, ok
}
