#!/bin/bash
# =================================================================
# Test script - STS OAuth 2.0 Token Opaco PoC (Camada Zero)
#
# Fluxo completo:
#   1. Gerar token opaco (client_credentials + token_opaco=true)
#   2. Gerar token JWT  (client_credentials + token_opaco=false)
#   3. Token Exchange (opaque -> JWT)
#   4. Introspecção do token opaco
#   5. Revogar token opaco
#   6. Verificar que token revogado é inativo
# =================================================================

set -e

ROUTER_URL="${ROUTER_URL:-http://localhost:9080}"
CELL_URL="${CELL_URL:-http://localhost:9081}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}  ✓ $1${NC}"; }
fail() { echo -e "${RED}  ✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${CYAN}═══════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════${NC}"; }

header "STS Token Opaco - Camada Zero - PoC Tests"

# --- Credenciais de teste (seeded no cmd/cell/main.go) ---
# App com token_opaco=true:
OPAQUE_CLIENT_ID="f8b87b48-3969-4308-9d68-df4d4949c212"
OPAQUE_CLIENT_SECRET="ea0abbaa-841a-461f-8981-c310dc1def5f"

# App com token_opaco=false (JWT):
JWT_CLIENT_ID="a1b2c3d4-5678-9012-3456-789012345678"
JWT_CLIENT_SECRET="bb1122cc-3344-5566-7788-99aabbccddee"

# ============================================================
info "Test 1: Router health check"
HEALTH=$(curl -s "$ROUTER_URL/health")
echo "  $HEALTH"
echo "$HEALTH" | grep -q '"status"' && pass "Router is up" || fail "Router health check failed"

# ============================================================
info "Test 2: List registered cells"
CELLS=$(curl -s "$ROUTER_URL/cells")
echo "  $CELLS" | python3 -m json.tool 2>/dev/null || echo "  $CELLS"
echo "$CELLS" | grep -q '"total"' && pass "Cells endpoint works" || fail "Cells endpoint failed"

# ============================================================
header "FLUXO 1: Geração de Token Opaco"
info "Test 3: Gerar token opaco (mesma request que JWT, mas token_opaco=true na credencial)"
echo "  curl -X POST $ROUTER_URL/api/oauth/token"
echo "    grant_type=client_credentials"
echo "    client_id=$OPAQUE_CLIENT_ID"
echo "    client_secret=$OPAQUE_CLIENT_SECRET"

OPAQUE_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET")
echo ""
echo "  Response:"
echo "  $OPAQUE_RESP" | python3 -m json.tool 2>/dev/null || echo "  $OPAQUE_RESP"

ACCESS_TOKEN=$(echo "$OPAQUE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -n "$ACCESS_TOKEN" ]; then
  TOKEN_PREFIX=$(echo "$ACCESS_TOKEN" | cut -d'.' -f1)
  TOKEN_CLIENT=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
  pass "Token opaco gerado!"
  echo -e "    Prefix (routing): ${CYAN}$TOKEN_PREFIX${NC}"
  echo -e "    Client ID:        ${CYAN}$TOKEN_CLIENT${NC}"
  echo -e "    Full token:       ${CYAN}${ACCESS_TOKEN:0:50}...${NC}"
else
  fail "Falha na geração do token opaco"
fi

# ============================================================
header "FLUXO 1b: Geração de Token JWT (token_opaco=false)"
info "Test 4: Gerar token JWT (mesma request, credencial diferente)"
JWT_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$JWT_CLIENT_ID" \
  -d "client_secret=$JWT_CLIENT_SECRET")
echo "  Response:"
echo "  $JWT_RESP" | python3 -m json.tool 2>/dev/null || echo "  $JWT_RESP"
echo "$JWT_RESP" | grep -q '"access_token"' && pass "Token JWT gerado!" || fail "Falha no JWT"

# ============================================================
header "FLUXO 2: Introspecção do Token Opaco"
info "Test 5: Verificar se token opaco está ativo (token_info)"
INTROSPECT=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")
echo "  Response:"
echo "  $INTROSPECT" | python3 -m json.tool 2>/dev/null || echo "  $INTROSPECT"
echo "$INTROSPECT" | grep -q '"active":true' && pass "Token está ATIVO" || fail "Introspecção falhou"

# ============================================================
info "Test 6: Introspecção via GET (tokeninfo)"
INTROSPECT_GET=$(curl -s "$ROUTER_URL/api/oauth/tokeninfo?token=$ACCESS_TOKEN")
echo "  $INTROSPECT_GET" | python3 -m json.tool 2>/dev/null || echo "  $INTROSPECT_GET"
echo "$INTROSPECT_GET" | grep -q '"active":true' && pass "GET introspect OK" || fail "GET introspect falhou"

# ============================================================
header "FLUXO 3: Token Exchange (Opaque → JWT)"
info "Test 7: Exchange token opaco por JWT"
echo "  curl -X POST $ROUTER_URL/api/oauth/token"
echo "    grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
echo "    subject_token=$ACCESS_TOKEN"
echo "    resource=urn:ietf:params:oauth:resource:opaque"

EXCHANGE_RESP=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "resource=urn:ietf:params:oauth:resource:opaque")
echo ""
echo "  Response:"
echo "  $EXCHANGE_RESP" | python3 -m json.tool 2>/dev/null || echo "  $EXCHANGE_RESP"

JWT_FROM_EXCHANGE=$(echo "$EXCHANGE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
if [ -n "$JWT_FROM_EXCHANGE" ] && [[ "$JWT_FROM_EXCHANGE" == eyJ* ]]; then
  pass "Exchange retornou JWT!"
  echo -e "    JWT: ${CYAN}${JWT_FROM_EXCHANGE:0:60}...${NC}"

  # Decode JWT payload
  JWT_PAYLOAD=$(echo "$JWT_FROM_EXCHANGE" | cut -d'.' -f2 | python3 -c "
import sys, base64, json
payload = sys.stdin.read().strip()
payload += '=' * (4 - len(payload) % 4)
data = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(data, indent=2))
" 2>/dev/null)
  if [ -n "$JWT_PAYLOAD" ]; then
    echo -e "    JWT Payload decoded:"
    echo "    $JWT_PAYLOAD"
  fi
else
  fail "Exchange falhou ou não retornou JWT"
fi

# ============================================================
header "FLUXO 4: Revogação de Token"
info "Test 8: Revogar token opaco"
echo "  curl -X POST $ROUTER_URL/api/oauth/token"
echo "    grant_type=token"
echo "    token=$ACCESS_TOKEN"

REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=token" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN")
[ "$REVOKE_STATUS" = "200" ] && pass "Token revogado (HTTP $REVOKE_STATUS)" || fail "Revoke falhou (HTTP $REVOKE_STATUS)"

# ============================================================
info "Test 9: Verificar que token revogado está inativo"
INTROSPECT_REVOKED=$(curl -s -X POST "$ROUTER_URL/api/oauth/token_info" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")
echo "  $INTROSPECT_REVOKED"
echo "$INTROSPECT_REVOKED" | grep -q '"active":false' && pass "Token revogado está INATIVO" || fail "Token deveria estar inativo"

# ============================================================
info "Test 10: Exchange com token revogado deve falhar"
EXCHANGE_REVOKED=$(curl -s -X POST "$ROUTER_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=$OPAQUE_CLIENT_ID" \
  -d "client_secret=$OPAQUE_CLIENT_SECRET" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "resource=urn:ietf:params:oauth:resource:opaque")
echo "  $EXCHANGE_REVOKED"
echo "$EXCHANGE_REVOKED" | grep -q '"error"' && pass "Exchange com token revogado rejeitado" || fail "Exchange deveria ter falhado"

# ============================================================
header "RESUMO"
echo ""
echo -e "${GREEN}  Todos os testes passaram!${NC}"
echo ""
echo "  Fluxo completo validado:"
echo "    1. ✓ Geração token opaco (token_opaco=true na credencial)"
echo "    2. ✓ Geração token JWT (token_opaco=false na credencial)"
echo "    3. ✓ Introspecção (POST token_info + GET tokeninfo)"
echo "    4. ✓ Token Exchange (opaque → JWT)"
echo "    5. ✓ Revogação + verificação de inatividade"
echo "    6. ✓ Exchange rejeitado após revogação"
echo ""
echo "  Arquitetura Camada Zero:"
echo "    - Compass Router roteia por prefixo do token"
echo "    - Cells independentes com token store próprio"
echo "    - N-1 rule: com 4 cells, cada opera a 75%"
echo ""
