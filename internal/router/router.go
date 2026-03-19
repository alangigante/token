package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alandtse/poc-cell-oauth/internal/cell"
	"github.com/alandtse/poc-cell-oauth/internal/mock"
	"github.com/alandtse/poc-cell-oauth/internal/oauth"
	"github.com/alandtse/poc-cell-oauth/pkg/models"
)

// Router is the thin Compass-like routing layer (Camada Zero).
// Routes requests to the correct cell based on:
//   - Token prefix (for exchange/revoke/introspect)
//   - Organization/tenant ID (for initial token generation)
//   - Least-loaded cell (fallback)
type Router struct {
	cellManager   *cell.Manager
	tenantMapping *mock.TenantCellMapping
	prefixMapping *mock.PrefixCellMapping
	httpClient    *http.Client
}

func New(
	cellManager *cell.Manager,
	tenantMapping *mock.TenantCellMapping,
	prefixMapping *mock.PrefixCellMapping,
) *Router {
	return &Router{
		cellManager:   cellManager,
		tenantMapping: tenantMapping,
		prefixMapping: prefixMapping,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (rt *Router) RegisterRoutes(mux *http.ServeMux) {
	// Main STS endpoint
	mux.HandleFunc("POST /api/oauth/token", rt.handleProxy)

	// Introspection endpoints
	mux.HandleFunc("POST /api/oauth/token_info", rt.handleProxy)
	mux.HandleFunc("POST /api/oauth/tokeninfo", rt.handleProxy)
	mux.HandleFunc("GET /api/oauth/token_info", rt.handleProxy)
	mux.HandleFunc("GET /api/oauth/tokeninfo", rt.handleProxy)

	// Token lookup endpoints (proxied to cells)
	mux.HandleFunc("GET /api/oauth/tokens", rt.handleProxy)
	mux.HandleFunc("GET /api/oauth/tokens/{token}", rt.handleProxyTokenLookup)

	// Management endpoints
	mux.HandleFunc("GET /cells", rt.handleListCells)
	mux.HandleFunc("POST /cells/register", rt.handleRegisterCell)
	mux.HandleFunc("POST /cells/prefix", rt.handleRegisterPrefix)
	mux.HandleFunc("GET /health", rt.handleRouterHealth)
	mux.HandleFunc("GET /", rt.handleInfo)
}

func (rt *Router) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Read body so we can inspect it AND forward it
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	r.Body.Close()

	targetCell, err := rt.resolveCell(r, bodyBytes)
	if err != nil {
		log.Printf("[router] cell resolution failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":             "service_unavailable",
			"error_description": err.Error(),
		})
		return
	}

	log.Printf("[router] routing %s %s -> cell %s (%s)",
		r.Method, r.URL.Path, targetCell.ID, targetCell.Address)

	rt.forwardRequest(w, r, targetCell, bodyBytes)
}

// resolveCell determines which cell handles this request.
// Routing strategies (in order of priority):
//  1. Token prefix → cell mapping (for exchange, revoke, introspect)
//  2. Organization/client → cell mapping (for new token generation)
//  3. Least loaded cell (fallback)
func (rt *Router) resolveCell(r *http.Request, body []byte) (*models.CellInfo, error) {
	params := parseFormBody(body)

	// Strategy 1: Route by token prefix (for exchange/revoke/introspect)
	// The opaque token prefix is used by Compass to route to the correct shard
	tokenStr := params.Get("subject_token") // token-exchange
	if tokenStr == "" {
		tokenStr = params.Get("token") // revoke/introspect
	}
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("token") // GET introspect
	}
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("access_token")
	}

	if tokenStr != "" {
		prefix, err := oauth.ExtractPrefix(tokenStr)
		if err == nil {
			if cellID, ok := rt.prefixMapping.Get(prefix); ok {
				if c, ok := rt.cellManager.GetCell(cellID); ok && c.Healthy {
					log.Printf("[router] routed by token prefix '%s' -> cell %s", prefix, cellID)
					return c, nil
				}
				log.Printf("[router] cell %s (prefix %s) is unhealthy, finding alternative", cellID, prefix)
			}
		}
	}

	// Strategy 2: Route by client_id (organization mapping)
	clientID := params.Get("client_id")
	if clientID != "" {
		if cellID, ok := rt.tenantMapping.Get(clientID); ok {
			if c, ok := rt.cellManager.GetCell(cellID); ok && c.Healthy {
				return c, nil
			}
			log.Printf("[router] client %s mapped to unhealthy cell, reassigning", clientID)
		}

		// Assign client to least loaded cell
		bestCell, err := rt.cellManager.GetLeastLoadedCell()
		if err != nil {
			return nil, err
		}
		rt.tenantMapping.Set(clientID, bestCell.ID)
		log.Printf("[router] assigned client %s -> cell %s", clientID, bestCell.ID)
		return bestCell, nil
	}

	// Strategy 3: Fallback
	return rt.cellManager.GetLeastLoadedCell()
}

func (rt *Router) forwardRequest(w http.ResponseWriter, r *http.Request, target *models.CellInfo, body []byte) {
	targetURL := fmt.Sprintf("http://%s%s", target.Address, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "proxy_error"})
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyReq.Header.Set("X-Forwarded-By", "compass-router")
	proxyReq.Header.Set("X-Target-Cell", target.ID)

	resp, err := rt.httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("[router] proxy error to cell %s: %v", target.ID, err)

		// Attempt failover to another cell
		log.Printf("[router] attempting failover for cell %s", target.ID)
		altCell, altErr := rt.cellManager.GetLeastLoadedCell()
		if altErr != nil || altCell.ID == target.ID {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "bad_gateway",
				"error_description": fmt.Sprintf("cell %s unreachable, no failover available", target.ID),
			})
			return
		}

		// Retry on alternative cell
		retryURL := fmt.Sprintf("http://%s%s", altCell.Address, r.URL.Path)
		if r.URL.RawQuery != "" {
			retryURL += "?" + r.URL.RawQuery
		}
		retryReq, _ := http.NewRequestWithContext(r.Context(), r.Method, retryURL, bytes.NewReader(body))
		for key, values := range r.Header {
			for _, v := range values {
				retryReq.Header.Add(key, v)
			}
		}
		resp, err = rt.httpClient.Do(retryReq)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "bad_gateway",
				"error_description": "all cells unreachable",
			})
			return
		}
		log.Printf("[router] failover successful: %s -> %s", target.ID, altCell.ID)
	}
	defer resp.Body.Close()

	// If response contains an opaque token, register its prefix for future routing
	if r.URL.Path == "/api/oauth/token" {
		rt.captureTokenPrefix(resp, target, w)
		return
	}

	// Copy response
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Cell-ID", target.ID)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// captureTokenPrefix intercepts the token response to register prefix->cell mapping.
func (rt *Router) captureTokenPrefix(resp *http.Response, target *models.CellInfo, w http.ResponseWriter) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to read cell response"})
		return
	}

	// Try to extract access_token from response to register prefix
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err == nil && tokenResp.AccessToken != "" {
		if prefix, err := oauth.ExtractPrefix(tokenResp.AccessToken); err == nil {
			rt.prefixMapping.Set(prefix, target.ID)
			log.Printf("[router] registered prefix '%s' -> cell %s", prefix, target.ID)
		}
	}

	// Forward response to client
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Cell-ID", target.ID)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleProxyTokenLookup routes GET /api/oauth/tokens/{token} by extracting the prefix from the token path param.
func (rt *Router) handleProxyTokenLookup(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.PathValue("token")

	if tokenStr != "" {
		prefix, err := oauth.ExtractPrefix(tokenStr)
		if err == nil {
			if cellID, ok := rt.prefixMapping.Get(prefix); ok {
				if c, ok := rt.cellManager.GetCell(cellID); ok && c.Healthy {
					log.Printf("[router] GET token lookup: prefix '%s' -> cell %s", prefix, cellID)
					rt.forwardRequest(w, r, c, nil)
					return
				}
			}
		}
	}

	// Fallback: try all healthy cells
	bestCell, err := rt.cellManager.GetLeastLoadedCell()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no cells available"})
		return
	}
	log.Printf("[router] GET token lookup: fallback -> cell %s", bestCell.ID)
	rt.forwardRequest(w, r, bestCell, nil)
}

func (rt *Router) handleListCells(w http.ResponseWriter, r *http.Request) {
	cells := rt.cellManager.GetAllCells()
	capacity := rt.cellManager.CalculateCapacityPerCell()

	writeJSON(w, http.StatusOK, map[string]any{
		"cells":                    cells,
		"total":                    len(cells),
		"healthy":                  len(rt.cellManager.GetHealthyCells()),
		"target_capacity_per_cell": capacity,
		"n_minus_1_rule":           fmt.Sprintf("Each cell operates at %.0f%% capacity", capacity*100),
	})
}

func (rt *Router) handleRegisterCell(w http.ResponseWriter, r *http.Request) {
	var cellInfo models.CellInfo
	if err := json.NewDecoder(r.Body).Decode(&cellInfo); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cell info"})
		return
	}

	rt.cellManager.Register(&cellInfo)
	writeJSON(w, http.StatusCreated, map[string]string{
		"status":  "registered",
		"cell_id": cellInfo.ID,
	})
}

func (rt *Router) handleRegisterPrefix(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prefix string `json:"prefix"`
		CellID string `json:"cell_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	rt.prefixMapping.Set(req.Prefix, req.CellID)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (rt *Router) handleRouterHealth(w http.ResponseWriter, r *http.Request) {
	healthy := rt.cellManager.GetHealthyCells()
	status := "healthy"
	if len(healthy) == 0 {
		status = "unhealthy"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":       "compass-router (camada zero)",
		"status":        status,
		"healthy_cells": len(healthy),
		"total_cells":   len(rt.cellManager.GetAllCells()),
	})
}

func (rt *Router) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "Compass Router (Camada Zero) - STS OAuth 2.0",
		"routing": map[string]string{
			"strategy_1": "Token prefix -> cell mapping (exchange/revoke/introspect)",
			"strategy_2": "Client ID -> cell mapping (token generation)",
			"strategy_3": "Least loaded cell (fallback)",
		},
		"endpoints": map[string]string{
			"POST /api/oauth/token":      "Generate token / Exchange / Revoke",
			"POST /api/oauth/token_info": "Introspect token",
			"GET  /api/oauth/tokeninfo":  "Introspect token (query param)",
			"GET  /cells":                "List all cells",
			"POST /cells/register":       "Register a cell",
			"GET  /health":               "Router health",
		},
	})
}

// OnCellDown handles cell failure by redistributing clients.
func (rt *Router) OnCellDown(failedCellID string) {
	log.Printf("[router] FAILOVER: cell %s is down, redistributing clients", failedCellID)

	tenants := rt.tenantMapping.GetTenantsByCell(failedCellID)
	healthyCells := rt.cellManager.GetHealthyCells()

	if len(healthyCells) == 0 {
		log.Printf("[router] CRITICAL: no healthy cells available for failover!")
		return
	}

	for i, clientID := range tenants {
		target := healthyCells[i%len(healthyCells)]
		rt.tenantMapping.Set(clientID, target.ID)
		log.Printf("[router] reassigned client %s -> cell %s", clientID, target.ID)
	}

	log.Printf("[router] failover complete: %d clients redistributed across %d cells",
		len(tenants), len(healthyCells))
}

// parseFormBody parses URL-encoded form data from a byte slice.
type formValues map[string]string

func (f formValues) Get(key string) string {
	return f[key]
}

func parseFormBody(body []byte) formValues {
	result := make(formValues)
	pairs := strings.Split(string(body), "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
