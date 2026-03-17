package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alandtse/poc-cell-oauth/internal/cell"
	"github.com/alandtse/poc-cell-oauth/internal/mock"
	"github.com/alandtse/poc-cell-oauth/internal/router"
)

func main() {
	port := getEnv("PORT", "9080")
	healthInterval := 10 * time.Second

	log.Println("==========================================================")
	log.Println("  Compass Router (Camada Zero) - STS OAuth 2.0 PoC")
	log.Println("==========================================================")

	tenantMapping := mock.NewTenantCellMapping()
	prefixMapping := mock.NewPrefixCellMapping()

	var cellRouter *router.Router

	cellManager := cell.NewManager(healthInterval, func(cellID string) {
		if cellRouter != nil {
			cellRouter.OnCellDown(cellID)
		}
	})

	cellRouter = router.New(cellManager, tenantMapping, prefixMapping)

	cellManager.StartHealthChecks()
	defer cellManager.Stop()

	mux := http.NewServeMux()
	cellRouter.RegisterRoutes(mux)

	addr := fmt.Sprintf(":%s", port)
	log.Printf("[router] listening on %s", addr)
	log.Println("[router] waiting for cells to register...")
	log.Println()
	log.Println("Routing strategies (Compass-like):")
	log.Println("  1. Token prefix   -> cell (exchange/revoke/introspect)")
	log.Println("  2. Client ID      -> cell (token generation)")
	log.Println("  3. Least loaded   -> cell (fallback)")
	log.Println()
	log.Println("Endpoints:")
	log.Println("  POST /api/oauth/token        - Generate / Exchange / Revoke")
	log.Println("  POST /api/oauth/token_info   - Introspect token")
	log.Println("  GET  /api/oauth/tokeninfo    - Introspect token (query)")
	log.Println("  GET  /cells                  - List cells")
	log.Println("  POST /cells/register         - Register cell")
	log.Println("  GET  /health                 - Router health")
	log.Println()

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("router error: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
