package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/alandtse/poc-cell-oauth/internal/mock"
	"github.com/alandtse/poc-cell-oauth/internal/oauth"
	"github.com/alandtse/poc-cell-oauth/pkg/models"
)

func main() {
	routerAddr := getEnv("ROUTER_ADDR", "localhost:9080")

	// Auto-detect cell ID and port if not explicitly set
	cellID, port := autoDetectCellConfig(routerAddr)
	env := getEnv("ENV", "D")
	site := getEnv("SITE", "dev")
	source := getEnv("SOURCE", "INT")
	issuer := getEnv("ISSUER", "https://openid.itua.com.br/api/oauth/token")

	log.Printf("Starting STS Cell [%s] on port %s", cellID, port)

	// Initialize stores (mocks — in prod: Cassandra for tokens, DynamoDB for apps)
	tokenStore := mock.NewTokenStore()
	appStore := mock.NewApplicationStore()
	prefixStore := mock.NewPrefixCellMapping()

	// Seed demo applications/credentials
	seedApplications(appStore)

	// JWT signing key (mock — in prod: RSA keys from HSM/KMS)
	jwtSecret := []byte(getEnv("JWT_SECRET", "poc-camada-zero-secret-key-32bytes!"))

	// Initialize token service and HTTP server
	tokenService := oauth.NewTokenService(
		cellID, env, site, source, issuer,
		jwtSecret, tokenStore, appStore, prefixStore,
	)
	server := oauth.NewServer(cellID, tokenService)

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Self-register with router
	go func() {
		time.Sleep(1 * time.Second)
		registerWithRouter(routerAddr, cellID, port)
	}()

	// Start token cleanup goroutine (simulates Cassandra TTL)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			tokenStore.Cleanup()
		}
	}()

	addr := fmt.Sprintf(":%s", port)
	log.Printf("[cell:%s] listening on %s", cellID, addr)
	log.Println()
	log.Println("  Flows:")
	log.Println("    1. Gerar token opaco:  POST /api/oauth/token  grant_type=client_credentials")
	log.Println("    2. Token exchange:     POST /api/oauth/token  grant_type=urn:ietf:params:oauth:grant-type:token-exchange")
	log.Println("    3. Revogar token:      POST /api/oauth/token  grant_type=token")
	log.Println("    4. Introspecção:       POST /api/oauth/token_info | GET /api/oauth/tokeninfo?token=...")
	log.Println("    5. Listar tokens:      GET  /api/oauth/tokens[?client_id=...]")
	log.Println("    6. Detalhe token:      GET  /api/oauth/tokens/{access_token}")
	log.Println()

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("cell server error: %v", err)
	}
}

// autoDetectCellConfig queries the router for existing cells and picks the next
// available cell ID and port automatically. If CELL_ID or PORT env vars are set,
// those take precedence.
func autoDetectCellConfig(routerAddr string) (cellID, port string) {
	// If explicitly set via env, use those
	envCellID := os.Getenv("CELL_ID")
	envPort := os.Getenv("PORT")
	if envCellID != "" && envPort != "" {
		return envCellID, envPort
	}

	basePort := 9081
	maxCellID := 0

	// Try to query the router for existing cells
	resp, err := http.Get(fmt.Sprintf("http://%s/cells", routerAddr))
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var cellsResp struct {
			Cells []struct {
				ID      string `json:"id"`
				Address string `json:"address"`
			} `json:"cells"`
			Total int `json:"total"`
		}
		if json.Unmarshal(body, &cellsResp) == nil && cellsResp.Total > 0 {
			for _, c := range cellsResp.Cells {
				// Extract cell number from "cell-N"
				var n int
				if _, err := fmt.Sscanf(c.ID, "cell-%d", &n); err == nil {
					if n > maxCellID {
						maxCellID = n
					}
				}
				// Track used ports
				if _, portStr, err := net.SplitHostPort(c.Address); err == nil {
					if p, err := strconv.Atoi(portStr); err == nil {
						if p >= basePort {
							basePort = p + 1
						}
					}
				}
			}
			log.Printf("[auto-detect] found %d existing cells, highest cell-id=%d", cellsResp.Total, maxCellID)
		}
	} else {
		log.Printf("[auto-detect] router not reachable yet, using defaults")
	}

	// If env vars partially set, fill in the missing one
	nextNum := maxCellID + 1
	if envCellID != "" {
		cellID = envCellID
	} else {
		cellID = fmt.Sprintf("cell-%d", nextNum)
	}

	if envPort != "" {
		port = envPort
	} else {
		port = strconv.Itoa(basePort)
		// Verify port is available, increment if not
		for i := 0; i < 10; i++ {
			ln, err := net.Listen("tcp", ":"+port)
			if err == nil {
				ln.Close()
				break
			}
			p, _ := strconv.Atoi(port)
			port = strconv.Itoa(p + 1)
		}
	}

	log.Printf("[auto-detect] selected cell_id=%s port=%s", cellID, port)
	return cellID, port
}

// seedApplications creates demo credentials matching the real STS format.
func seedApplications(store *mock.ApplicationStore) {
	apps := []*models.Application{
		{
			// App with token_opaco=true — generates opaque tokens
			ID:             "f8b87b48-3969-4308-9d68-df4d4949c212",
			Name:           "#APP Gateway",
			Description:    "Aplicacao exclusiva para uso do gateway para recuperar as chaves RSA",
			OrganizationID: "afe06c9c-33d7-41c1-932b-91972e5fa730",
			Email:          "gateway@example.com",
			CreatedBy:      "375e98c6-96c2-4412-b9a5-f1e7d13cd202",
			ManagedBy:      []string{},
			CreatedOn:      1539688653891,
			Enabled:        true,
			State:          "approved",
			UsarRevoke:     false,
			TokenOpaco:     true, // <-- THIS enables opaque token generation
			ReqCertificado: false,
			AplicaRSA:      false,
			Provider:       "AD",
			ReqFlowID:      false,
			ClientSecret:   "ea0abbaa-841a-461f-8981-c310dc1def5f",
			Scopes:         []string{"resource.WRITE", "scope.TEST", "resource.READ", "example_restrito.write", "rsa.GATEWAY_PUBLIC_KEY"},
		},
		{
			// App with token_opaco=false — generates JWT tokens
			ID:             "a1b2c3d4-5678-9012-3456-789012345678",
			Name:           "#APP API Service",
			Description:    "Aplicacao de servico que usa token JWT",
			OrganizationID: "afe06c9c-33d7-41c1-932b-91972e5fa730",
			Email:          "api@example.com",
			CreatedBy:      "375e98c6-96c2-4412-b9a5-f1e7d13cd202",
			ManagedBy:      []string{},
			CreatedOn:      1539688653891,
			Enabled:        true,
			State:          "approved",
			UsarRevoke:     false,
			TokenOpaco:     false, // <-- JWT flow
			ReqCertificado: false,
			AplicaRSA:      true,
			Provider:       "AD",
			ReqFlowID:      false,
			ClientSecret:   "bb1122cc-3344-5566-7788-99aabbccddee",
			Scopes:         []string{"resource.READ", "resource.WRITE"},
		},
		{
			// Another opaque-enabled app for a different org
			ID:             "11111111-2222-3333-4444-555555555555",
			Name:           "#APP Parceiros",
			Description:    "Aplicacao para parceiros com token opaco",
			OrganizationID: "bbb06c9c-33d7-41c1-932b-91972e5fa730",
			Email:          "parceiros@example.com",
			CreatedBy:      "375e98c6-96c2-4412-b9a5-f1e7d13cd202",
			ManagedBy:      []string{},
			CreatedOn:      1639688653891,
			Enabled:        true,
			State:          "approved",
			UsarRevoke:     true,
			TokenOpaco:     true,
			ReqCertificado: false,
			AplicaRSA:      false,
			Provider:       "LDAP",
			ReqFlowID:      false,
			ClientSecret:   "cc2233dd-4455-6677-8899-aabbccddeeff",
			Scopes:         []string{"resource.READ", "partner.WRITE"},
		},
	}

	for _, a := range apps {
		if err := store.Register(a); err != nil {
			log.Printf("failed to register app %s: %v", a.ID, err)
		}
	}
	log.Printf("seeded %d applications (%d with token_opaco=true)",
		len(apps), countOpaque(apps))
}

func countOpaque(apps []*models.Application) int {
	n := 0
	for _, a := range apps {
		if a.TokenOpaco {
			n++
		}
	}
	return n
}

func registerWithRouter(routerAddr, cellID, port string) {
	cellInfo := models.CellInfo{
		ID:          cellID,
		Address:     fmt.Sprintf("localhost:%s", port),
		Healthy:     true,
		MaxCapacity: 1000,
	}

	body, _ := json.Marshal(cellInfo)

	for i := 0; i < 10; i++ {
		resp, err := http.Post(
			fmt.Sprintf("http://%s/cells/register", routerAddr),
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			log.Printf("[cell:%s] failed to register with router (attempt %d): %v", cellID, i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			log.Printf("[cell:%s] registered with router at %s", cellID, routerAddr)
			return
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("[cell:%s] WARNING: could not register with router, running standalone", cellID)
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
