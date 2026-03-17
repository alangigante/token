package oauth

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const (
	GrantClientCredentials = "client_credentials"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTokenRevoke       = "token" // custom grant for revocation
)

// Server is the per-cell STS (Security Token Service) OAuth 2.0 server.
type Server struct {
	cellID       string
	tokenService *TokenService
	startTime    time.Time
}

func NewServer(cellID string, tokenService *TokenService) *Server {
	return &Server{
		cellID:       cellID,
		tokenService: tokenService,
		startTime:    time.Now(),
	}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Single endpoint for all OAuth operations — same as real STS
	mux.HandleFunc("POST /api/oauth/token", s.handleToken)

	// Introspection endpoints (token_info and tokeninfo)
	mux.HandleFunc("POST /api/oauth/token_info", s.handleIntrospect)
	mux.HandleFunc("POST /api/oauth/tokeninfo", s.handleIntrospect)
	mux.HandleFunc("GET /api/oauth/token_info", s.handleIntrospectGet)
	mux.HandleFunc("GET /api/oauth/tokeninfo", s.handleIntrospectGet)

	// Health and info
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /", s.handleInfo)
}

// handleToken is the unified token endpoint — routes by grant_type.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case GrantClientCredentials:
		s.handleClientCredentials(w, r)
	case GrantTokenExchange:
		s.handleTokenExchange(w, r)
	case GrantTokenRevoke:
		s.handleRevoke(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported: client_credentials, urn:ietf:params:oauth:grant-type:token-exchange, token")
	}
}

// handleClientCredentials — issues opaque token OR JWT depending on credential's token_opaco flag.
// The request is EXACTLY the same for both; the server decides based on the application config.
func (s *Server) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusUnauthorized, "invalid_client", "missing client_id or client_secret")
		return
	}

	// Check if application uses opaque tokens
	app, err := s.tokenService.appStore.Get(clientID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "application not found")
		return
	}

	if app.TokenOpaco {
		// Issue OPAQUE token
		resp, err := s.tokenService.IssueOpaqueToken(clientID, clientSecret)
		if err != nil {
			log.Printf("[cell:%s] opaque token error: %v", s.cellID, err)
			writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		log.Printf("[cell:%s] issued OPAQUE token for client=%s prefix=%s",
			s.cellID, clientID, extractPrefixFromResponse(resp.AccessToken))
		writeJSON(w, http.StatusOK, resp)
	} else {
		// Issue JWT token
		resp, err := s.tokenService.IssueJWTToken(clientID, clientSecret)
		if err != nil {
			log.Printf("[cell:%s] jwt token error: %v", s.cellID, err)
			writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		log.Printf("[cell:%s] issued JWT token for client=%s", s.cellID, clientID)
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleTokenExchange — exchanges an opaque subject_token for a JWT.
// grant_type=urn:ietf:params:oauth:grant-type:token-exchange
// Required params: client_id, client_secret, subject_token, resource
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	subjectToken := r.FormValue("subject_token")
	resource := r.FormValue("resource")

	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusUnauthorized, "invalid_client", "missing client_id or client_secret")
		return
	}

	if subjectToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing subject_token")
		return
	}

	resp, err := s.tokenService.ExchangeToken(clientID, clientSecret, subjectToken, resource)
	if err != nil {
		log.Printf("[cell:%s] token exchange error: %v", s.cellID, err)
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	log.Printf("[cell:%s] token EXCHANGE for client=%s subject_token_prefix=%s",
		s.cellID, clientID, extractPrefixFromResponse(subjectToken))
	writeJSON(w, http.StatusOK, resp)
}

// handleRevoke — revokes an opaque token from the database.
// grant_type=token
// Returns 200 OK with empty body on success.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	tokenStr := r.FormValue("token")

	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusUnauthorized, "invalid_client", "missing client_id or client_secret")
		return
	}

	if tokenStr == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing token")
		return
	}

	if err := s.tokenService.RevokeToken(clientID, clientSecret, tokenStr); err != nil {
		log.Printf("[cell:%s] revoke error: %v", s.cellID, err)
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	log.Printf("[cell:%s] REVOKED token for client=%s", s.cellID, clientID)
	w.WriteHeader(http.StatusOK)
}

// handleIntrospect — validates if an opaque token is active (POST).
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing token parameter")
		return
	}

	resp, err := s.tokenService.Introspect(token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleIntrospectGet — validates if an opaque token is active (GET with query param).
func (s *Server) handleIntrospectGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.URL.Query().Get("access_token")
	}
	if token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing token parameter")
		return
	}

	resp, err := s.tokenService.Introspect(token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := int64(time.Since(s.startTime).Seconds())
	writeJSON(w, http.StatusOK, map[string]any{
		"cell_id":        s.cellID,
		"status":         "healthy",
		"current_load":   0.5, // mock
		"uptime_seconds": uptime,
	})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "STS - Security Token Service (Cell-based)",
		"cell_id": s.cellID,
		"flows": map[string]string{
			"opaque_token":   "POST /api/oauth/token (grant_type=client_credentials, token_opaco=true)",
			"jwt_token":      "POST /api/oauth/token (grant_type=client_credentials, token_opaco=false)",
			"token_exchange": "POST /api/oauth/token (grant_type=urn:ietf:params:oauth:grant-type:token-exchange)",
			"revoke":         "POST /api/oauth/token (grant_type=token)",
			"introspect":     "POST /api/oauth/token_info | GET /api/oauth/tokeninfo?token=...",
		},
	})
}

func extractPrefixFromResponse(token string) string {
	p, _ := ExtractPrefix(token)
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
