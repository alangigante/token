#!/usr/bin/env bash
# =================================================================
# Test script - STS OAuth 2.0 Token Opaco PoC (Camada Zero)
# Zero external dependencies (no python needed)
#
# Cobertura completa:
#   1.  Health check do router
#   2.  Health check direto da cell
#   3.  List cells registradas
#   4.  Router info endpoint
#   5.  Gerar token opaco (token_opaco=true)
#   6.  GET token - consultar token gerado
#   7.  List tokens - listar todos os tokens
#   8.  Gerar token JWT (token_opaco=false)
#   9.  Introspecção POST (token_info)
#   10. Introspecção GET  (tokeninfo)
#   11. Token Exchange (opaque -> JWT)
#   12. Gerar token opaco com segunda credencial (org diferente)
#   13. List tokens filtrado por client_id
#   14. Introspect token parceiros
#   15. Revogar token opaco
#   16. Verificar token revogado está inativo
#   17. GET token revogado - verificar status
#   18. Exchange com token revogado deve falhar
#   19. Credencial inválida deve ser rejeitada
#   20. Grant type inválido deve ser rejeitado
#   21. Client ID inexistente deve falhar
#   22. Introspect com token inexistente
#   23. Exchange sem subject_token deve falhar
#   24. Revoke sem token deve falhar
#   25. Token parceiros ainda ativo após revogar Gateway
#   26. List tokens final
# =================================================================

set -e

ROUTER_URL="${ROUTER_URL:-http://localhost:9080}"
CELL_URL="${CELL_URL:-http://localhost:9081}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TEST_NUM=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}✓ $1${NC}"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}✗ $1${NC}"; }
info() { TEST_NUM=$((TEST_NUM + 1)); echo -e "\n${YELLOW}[$TEST_NUM] $1${NC}"; }
header() { echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"; }
detail() { echo -e "  ${GRAY}$1${NC}"; }
separator() { echo -e "${GRAY}  ─────────────────────────────────────────────${NC}"; }

# Pure bash JSON helpers (no python needed)
json_val() {
  local json="$1" key="$2"
  echo "$json" | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*[^,}]*" | head -1 | sed 's/.*:[[:space:]]*//' | sed 's/^"//;s/"$//' | sed 's/[[:space:]]*$//'
}

json_print() {
  echo -e "  ${GRAY}$1${NC}"
}

# --- Credenciais de teste ---
OPAQUE_CLIENT_ID="f8b87b48-3969-4308-9d68-df4d4949c212"
OPAQUE_CLIENT_SECRET="ea0abbaa-841a-461f-8981-c310dc1def5f"

JWT_CLIENT_ID="a1b2c3d4-5678-9012-3456-789012345678"
JWT_CLIENT_SECRET="bb1122cc-3344-5566-7788-99aabbccddee"

PARTNER_CLIENT_ID="11111111-2222-3333-4444-555555555555"
PARTNER_CLIENT_SECRET="cc2233dd-4455-6677-8899-aabbccddeeff"

header "STS Token Opaco - Camada Zero - PoC Tests"
echo -e "  Router: ${CYAN}$ROUTER_URL${NC}"
echo -e "  Cell:   ${CYAN}$CELL_URL${NC}"
echo -e "  Time:   ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${NC}"

# ============================================================
header "INFRAESTRUTURA"
# ============================================================

info "Router health check"
detail "curl -s $ROUTER_URL/health"
HEALTH=$(curl -s "$ROUTER_URL/health")
json_print "$HEALTH"
echo "$HEALTH" | grep -q '"status"' && pass "Router is up" || fail "Router health check failed"

info "Cell health check (direto)"
detail "curl -s $CELL_URL/health"
CELL_HEALTH=$(curl -s "$CELL_URL/health")
json_print "$CELL_HEALTH"
echo "$CELL_HEALTH" | grep -q '"healthy"' && pass "Cell is healthy" || fail "Cell health failed"

CELL_ID=$(json_val "$CELL_HEALTH" "cell_id")
detail "Cell ID: $CELL_ID"

info "List registered cells"
detail "curl -s $ROUTER_URL/cells"
CELLS=$(curl -s "$ROUTER_URL/cells")
json_print "$CELLS"
CELL_COUNT=$(json_val "$CELLS" "total")
HEALTHY_COUNT=$(json_val "$CELLS" "healthy")
echo "$CELLS" | grep -q '"total"' && pass "Cells endpoint works (total=$CELL_COUNT, healthy=$HEALTHY_COUNT)" || fail "Cells endpoint failed"

info "Router info endpoint"
detail "curl -s $ROUTER_URL/"
ROOT_INFO=$(curl -s "$ROUTER_URL/")
json_print "$ROOT_INFO"
echo "$ROOT_INFO" | grep -q 'Compass Router' && pass "Router info OK" || fail "Router info failed"

# ============================================================
header "FLUXO 1: GERACAO DE TOKEN OPACO (token_opaco=true)"
# ============================================================

info "Gerar token opaco - credencial Gateway"
detail "POST $ROUTER_URL/api/oauth/token"
detail "  grant_type=client_credentials"
detail "  client_id=$OPAQUE_CLIENT_ID"
detail "  client_secret=ea0abbaa-****"
separator

OPAQUE_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET")
json_print "$OPAQUE_RESP"

ACCESS_TOKEN=$(json_val "$OPAQUE_RESP" "access_token")

if [ -n "$ACCESS_TOKEN" ]; then
  TOKEN_PREFIX=$(echo "$ACCESS_TOKEN" | cut -d'.' -f1)
  TOKEN_CLIENT=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
  TOKEN_SUFFIX=$(echo "$ACCESS_TOKEN" | cut -d'.' -f3)
  pass "Token opaco gerado!"
  detail "Prefix (routing): $TOKEN_PREFIX"
  detail "Client ID:        $TOKEN_CLIENT"
  detail "Suffix:           ${TOKEN_SUFFIX:0:8}..."
  detail "Full token:       ${ACCESS_TOKEN:0:60}..."

  TOKEN_SUB=$(json_val "$OPAQUE_RESP" "sub")
  TOKEN_ISS=$(json_val "$OPAQUE_RESP" "iss")
  TOKEN_EXP=$(json_val "$OPAQUE_RESP" "expires_in")
  TOKEN_SRC=$(json_val "$OPAQUE_RESP" "source")
  TOKEN_ENV=$(json_val "$OPAQUE_RESP" "env")
  TOKEN_FLOW=$(json_val "$OPAQUE_RESP" "flow")
  detail "sub=$TOKEN_SUB iss=$TOKEN_ISS expires_in=$TOKEN_EXP source=$TOKEN_SRC env=$TOKEN_ENV flow=$TOKEN_FLOW"
else
  fail "Falha na geracao do token opaco"
fi

# ============================================================
header "FLUXO 1b: CONSULTAR TOKEN GERADO (GET)"
# ============================================================

info "GET token details (via router)"
detail "GET $ROUTER_URL/api/oauth/tokens/{access_token}"
TOKEN_DETAIL=$(curl -s "$ROUTER_URL/api/oauth/tokens/$ACCESS_TOKEN")
json_print "$TOKEN_DETAIL"

TOKEN_DETAIL_ACTIVE=$(json_val "$TOKEN_DETAIL" "active")
TOKEN_DETAIL_PREFIX=$(json_val "$TOKEN_DETAIL" "prefix")
TOKEN_DETAIL_CELL=$(json_val "$TOKEN_DETAIL" "cell_id")
TOKEN_DETAIL_EXP=$(json_val "$TOKEN_DETAIL" "expires_in_seconds")

if [ "$TOKEN_DETAIL_ACTIVE" = "true" ]; then
  pass "Token consultado via GET: active=true prefix=$TOKEN_DETAIL_PREFIX cell=$TOKEN_DETAIL_CELL expires_in=${TOKEN_DETAIL_EXP}s"
else
  fail "GET token retornou active=$TOKEN_DETAIL_ACTIVE"
fi

info "List all tokens"
detail "GET $ROUTER_URL/api/oauth/tokens"
TOKEN_LIST=$(curl -s "$ROUTER_URL/api/oauth/tokens")
json_print "$TOKEN_LIST"

LIST_TOTAL=$(json_val "$TOKEN_LIST" "total")
LIST_ACTIVE=$(json_val "$TOKEN_LIST" "active")
[ "${LIST_TOTAL:-0}" -ge 1 ] 2>/dev/null && pass "Token listado (total=$LIST_TOTAL, active=$LIST_ACTIVE)" || fail "List tokens vazia"

# ============================================================
header "FLUXO 2: GERACAO DE TOKEN JWT (token_opaco=false)"
# ============================================================

info "Gerar token JWT (credencial API Service, token_opaco=false)"
detail "POST $ROUTER_URL/api/oauth/token"
detail "  client_id=$JWT_CLIENT_ID"
JWT_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$JWT_CLIENT_ID" \
  -d "client_secret=$JWT_CLIENT_SECRET")
json_print "$JWT_RESP"

JWT_ACCESS=$(json_val "$JWT_RESP" "access_token")
if [[ "$JWT_ACCESS" == eyJ* ]]; then
  pass "Token JWT gerado (comeca com eyJ...)"
  detail "JWT: ${JWT_ACCESS:0:60}..."
else
  fail "Token JWT nao foi gerado ou nao comeca com eyJ"
fi

# ============================================================
header "FLUXO 3: INTROSPECCAO DO TOKEN OPACO"
# ============================================================

info "Introspeccao POST (token_info)"
detail "POST $ROUTER_URL/api/oauth/token_info"
detail "  token=${ACCESS_TOKEN:0:40}..."
INTROSPECT=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")
json_print "$INTROSPECT"
echo "$INTROSPECT" | grep -q '"active":true' && pass "Token esta ATIVO (POST)" || fail "Introspeccao POST falhou"

info "Introspeccao GET (tokeninfo)"
detail "GET $ROUTER_URL/api/oauth/tokeninfo?token=..."
INTROSPECT_GET=$(curl -s "$ROUTER_URL/api/oauth/tokeninfo?token=$ACCESS_TOKEN")
json_print "$INTROSPECT_GET"
echo "$INTROSPECT_GET" | grep -q '"active":true' && pass "Token esta ATIVO (GET)" || fail "Introspeccao GET falhou"

# ============================================================
header "FLUXO 4: TOKEN EXCHANGE (Opaque -> JWT)"
# ============================================================

info "Exchange token opaco por JWT"
detail "POST $ROUTER_URL/api/oauth/token"
detail "  grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
detail "  subject_token=${ACCESS_TOKEN:0:40}..."
detail "  resource=urn:ietf:params:oauth:resource:opaque"
separator

EXCHANGE_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "resource=urn:ietf:params:oauth:resource:opaque")
json_print "$EXCHANGE_RESP"

JWT_FROM_EXCHANGE=$(json_val "$EXCHANGE_RESP" "access_token")
EXCHANGE_SCOPE=$(json_val "$EXCHANGE_RESP" "scope")
EXCHANGE_TYPE=$(json_val "$EXCHANGE_RESP" "issued_token_type")
EXCHANGE_ACTIVE=$(json_val "$EXCHANGE_RESP" "active")

if [ -n "$JWT_FROM_EXCHANGE" ] && [[ "$JWT_FROM_EXCHANGE" == eyJ* ]]; then
  pass "Exchange retornou JWT!"
  detail "JWT: ${JWT_FROM_EXCHANGE:0:60}..."
  detail "scope=$EXCHANGE_SCOPE issued_token_type=$EXCHANGE_TYPE active=$EXCHANGE_ACTIVE"
else
  fail "Exchange falhou ou nao retornou JWT"
fi

# ============================================================
header "FLUXO 5: MULTI-TENANT (Segunda credencial, org diferente)"
# ============================================================

info "Gerar token opaco - credencial Parceiros (org diferente)"
detail "client_id=$PARTNER_CLIENT_ID"
PARTNER_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$PARTNER_CLIENT_ID" \
  -d "client_secret=$PARTNER_CLIENT_SECRET")
json_print "$PARTNER_RESP"

PARTNER_TOKEN=$(json_val "$PARTNER_RESP" "access_token")
if [ -n "$PARTNER_TOKEN" ]; then
  PARTNER_PREFIX=$(echo "$PARTNER_TOKEN" | cut -d'.' -f1)
  pass "Token parceiros gerado! prefix=$PARTNER_PREFIX"
else
  fail "Token parceiros falhou"
fi

info "List tokens filtrado por client_id (Gateway)"
detail "GET $ROUTER_URL/api/oauth/tokens?client_id=$OPAQUE_CLIENT_ID"
FILTERED_LIST=$(curl -s "$ROUTER_URL/api/oauth/tokens?client_id=$OPAQUE_CLIENT_ID")
json_print "$FILTERED_LIST"
FILTERED_TOTAL=$(json_val "$FILTERED_LIST" "total")
[ "${FILTERED_TOTAL:-0}" -ge 1 ] 2>/dev/null && pass "Filtro por client_id OK ($FILTERED_TOTAL tokens)" || fail "Filtro por client_id falhou"

info "Introspect token parceiros"
PARTNER_INTROSPECT=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$PARTNER_TOKEN")
json_print "$PARTNER_INTROSPECT"
echo "$PARTNER_INTROSPECT" | grep -q '"active":true' && pass "Token parceiros ativo" || fail "Token parceiros inativo"

# ============================================================
header "FLUXO 6: REVOGACAO DE TOKEN"
# ============================================================

info "Revogar token opaco (Gateway)"
detail "POST $ROUTER_URL/api/oauth/token"
detail "  grant_type=token"
detail "  token=${ACCESS_TOKEN:0:40}..."

REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=token" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN")
[ "$REVOKE_STATUS" = "200" ] && pass "Token revogado (HTTP $REVOKE_STATUS)" || fail "Revoke falhou (HTTP $REVOKE_STATUS)"

info "Verificar token revogado esta inativo (POST introspect)"
INTROSPECT_REVOKED=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")
json_print "$INTROSPECT_REVOKED"
echo "$INTROSPECT_REVOKED" | grep -q '"active":false' && pass "Token revogado esta INATIVO" || fail "Token deveria estar inativo"

info "GET token revogado - verificar status via GET"
REVOKED_DETAIL=$(curl -s "$ROUTER_URL/api/oauth/tokens/$ACCESS_TOKEN")
json_print "$REVOKED_DETAIL"
REVOKED_ACTIVE=$(json_val "$REVOKED_DETAIL" "active")
[ "$REVOKED_ACTIVE" = "false" ] && pass "GET confirma token revogado (active=false)" || fail "GET mostra token como ativo"

info "Exchange com token revogado deve falhar"
EXCHANGE_REVOKED=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "resource=urn:ietf:params:oauth:resource:opaque")
json_print "$EXCHANGE_REVOKED"
echo "$EXCHANGE_REVOKED" | grep -q '"error"' && pass "Exchange com token revogado REJEITADO" || fail "Exchange deveria ter falhado"

# ============================================================
header "FLUXO 7: CASOS DE ERRO"
# ============================================================

info "Credencial invalida deve ser rejeitada"
detail "client_secret=wrong-secret"
ERR_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=wrong-secret")
json_print "$ERR_RESP"
echo "$ERR_RESP" | grep -q '"error"' && pass "Credencial invalida rejeitada" || fail "Credencial invalida aceita"

info "Grant type invalido deve ser rejeitado"
detail "grant_type=invalid_grant"
ERR_GRANT=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=invalid_grant" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET")
json_print "$ERR_GRANT"
echo "$ERR_GRANT" | grep -q '"unsupported_grant_type"' && pass "Grant type invalido rejeitado" || fail "Grant type invalido aceito"

info "Client ID inexistente deve falhar"
detail "client_id=nonexistent-client"
ERR_CLIENT=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=nonexistent-client" \
  -d "client_secret=any-secret")
json_print "$ERR_CLIENT"
echo "$ERR_CLIENT" | grep -q '"error"' && pass "Client inexistente rejeitado" || fail "Client inexistente aceito"

info "Introspect com token inexistente deve retornar inactive"
INTROSPECT_FAKE=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=fake.token.value")
json_print "$INTROSPECT_FAKE"
echo "$INTROSPECT_FAKE" | grep -q '"active":false' && pass "Token inexistente e inativo" || fail "Token inexistente retornou ativo"

info "Exchange sem subject_token deve falhar"
ERR_EXCHANGE=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "resource=urn:ietf:params:oauth:resource:opaque")
json_print "$ERR_EXCHANGE"
echo "$ERR_EXCHANGE" | grep -q '"error"' && pass "Exchange sem subject_token rejeitado" || fail "Exchange sem subject_token aceito"

info "Revoke sem token deve falhar"
ERR_REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=token" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET")
[ "$ERR_REVOKE_STATUS" != "200" ] && pass "Revoke sem token rejeitado (HTTP $ERR_REVOKE_STATUS)" || fail "Revoke sem token aceito"

# ============================================================
header "FLUXO 8: VERIFICACAO POS-REVOGACAO"
# ============================================================

info "Token parceiros (outra org) ainda deve estar ativo apos revogar Gateway"
PARTNER_CHECK=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$PARTNER_TOKEN")
json_print "$PARTNER_CHECK"
echo "$PARTNER_CHECK" | grep -q '"active":true' && pass "Token parceiros AINDA ativo (isolamento OK)" || fail "Token parceiros afetado pela revogacao do Gateway"

info "List tokens final - verificar estado geral"
FINAL_LIST=$(curl -s "$ROUTER_URL/api/oauth/tokens")
FINAL_TOTAL=$(json_val "$FINAL_LIST" "total")
FINAL_ACTIVE=$(json_val "$FINAL_LIST" "active")
json_print "$FINAL_LIST"
pass "Estado final: total=$FINAL_TOTAL tokens, active=$FINAL_ACTIVE"

# ============================================================
header "RESUMO"
# ============================================================
echo ""
TOTAL=$((PASS_COUNT + FAIL_COUNT))
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}Todos os $TOTAL testes passaram! ($PASS_COUNT/$TOTAL)${NC}"
else
  echo -e "  ${RED}${BOLD}$FAIL_COUNT de $TOTAL testes falharam${NC}"
  echo -e "  ${GREEN}Passou: $PASS_COUNT${NC}  ${RED}Falhou: $FAIL_COUNT${NC}"
fi
echo ""
echo "  Cobertura de fluxos:"
echo "    1. Geracao token opaco (token_opaco=true na credencial)"
echo "    2. Geracao token JWT (token_opaco=false na credencial)"
echo "    3. Consulta de token via GET /api/oauth/tokens/{token}"
echo "    4. Listagem de tokens GET /api/oauth/tokens[?client_id=]"
echo "    5. Introspeccao (POST token_info + GET tokeninfo)"
echo "    6. Token Exchange (opaque -> JWT)"
echo "    7. Multi-tenant (credenciais de orgs diferentes)"
echo "    8. Revogacao + verificacao de inatividade"
echo "    9. Exchange rejeitado apos revogacao"
echo "    10. Isolamento: revogacao nao afeta outras orgs"
echo "    11. Casos de erro (credencial invalida, grant invalido, client inexistente)"
echo "    12. Token inexistente retorna inactive"
echo ""
echo "  Arquitetura Camada Zero:"
echo "    - Compass Router roteia por prefixo do token"
echo "    - Cells independentes com token store proprio"
echo "    - N-1 rule: com 4 cells, cada opera a 75%"
echo ""

exit $FAIL_COUNT
