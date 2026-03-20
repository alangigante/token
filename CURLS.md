# STS OAuth 2.0 Token Opaco - Guia de Curls

## Pre-requisitos

Inicie o router e pelo menos uma cell antes de executar os curls:

```bash
# Terminal 1: Router
go run ./cmd/router

# Terminal 2: Cell (auto-detecta ID e porta)
go run ./cmd/cell
```

---

## Credenciais de Teste

| App | Client ID | Client Secret | token_opaco | Org |
|-----|-----------|---------------|-------------|-----|
| #APP Gateway | `f8b87b48-3969-4308-9d68-df4d4949c212` | `ea0abbaa-841a-461f-8981-c310dc1def5f` | `true` | afe06c9c |
| #APP API Service | `a1b2c3d4-5678-9012-3456-789012345678` | `bb1122cc-3344-5566-7788-99aabbccddee` | `false` | afe06c9c |
| #APP Parceiros | `11111111-2222-3333-4444-555555555555` | `cc2233dd-4455-6677-8899-aabbccddeeff` | `true` | bbb06c9c |

---

## 1. Health Check

### Router
```bash
curl -s http://localhost:9080/health
```

### Cell (direto)
```bash
curl -s http://localhost:9081/health
```

### Info do Router
```bash
curl -s http://localhost:9080/
```

### Listar Cells Registradas
```bash
curl -s http://localhost:9080/cells
```

---

## 2. Gerar Token Opaco (token_opaco=true)

A credencial `#APP Gateway` tem `token_opaco=true`. A requisicao e identica a de JWT.

```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f"
```

**Resposta esperada:**
```json
{
  "sub": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "iss": "https://openid.itua.com.br/api/oauth/token",
  "access_token": "YepELzf3Y4lL2.f8b87b48-3969-4308-9d68-df4d4949c212.DkqvRS7a73LYIkbIBmnyF",
  "expires_in": "1209600",
  "source": "INT",
  "env": "D",
  "site": "dev",
  "flow": "CC"
}
```

> **Formato do token:** `{prefix}.{client_id}.{suffix}`
> - `prefix` = usado pelo Compass Router para rotear
> - `client_id` = UUID da credencial
> - `suffix` = random para unicidade

---

## 3. Gerar Token JWT (token_opaco=false)

A credencial `#APP API Service` tem `token_opaco=false`. Mesma requisicao, resposta diferente.

```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=a1b2c3d4-5678-9012-3456-789012345678" \
  -d "client_secret=bb1122cc-3344-5566-7788-99aabbccddee"
```

**Resposta esperada:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1209600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "resource.READ resource.WRITE"
}
```

---

## 4. Token Exchange (Opaque -> JWT)

Quando uma API recebe um token opaco, ela chama o STS para trocar por um JWT.

> **Substitua** `{TOKEN_OPACO}` pelo `access_token` obtido no passo 2.

```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "subject_token={TOKEN_OPACO}" \
  -d "resource=urn:ietf:params:oauth:resource:opaque"
```

**Resposta esperada:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1209600,
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "scope": "resource.WRITE scope.TEST resource.READ example_restrito.write rsa.GATEWAY_PUBLIC_KEY",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "active": true
}
```

**Decodificar o JWT retornado (payload):**
```bash
echo "{JWT_ACCESS_TOKEN}" | cut -d. -f2 | base64 -d
```

---

## 5. Introspecao de Token

Validacao online se o token esta ativo.

### POST (token_info)

```bash
curl -s -X POST http://localhost:9080/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token={TOKEN_OPACO}"
```

### GET (tokeninfo)

```bash
curl -s "http://localhost:9080/api/oauth/tokeninfo?token={TOKEN_OPACO}"
```

**Resposta esperada (token ativo):**
```json
{
  "active": true,
  "scope": "resource.WRITE scope.TEST resource.READ example_restrito.write rsa.GATEWAY_PUBLIC_KEY",
  "client_id": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "token_type": "opaque",
  "cell_id": "cell-1",
  "source": "INT",
  "env": "D",
  "flow": "CC"
}
```

**Resposta esperada (token inativo/revogado):**
```json
{
  "active": false
}
```

---

## 6. Consultar Token (GET)

### Detalhe de um token especifico

```bash
curl -s "http://localhost:9080/api/oauth/tokens/{TOKEN_OPACO}"
```

**Resposta esperada:**
```json
{
  "token": "YepELzf3Y4lL2.f8b87b48-...-c212.DkqvRS7a73LYIkbIBmnyF",
  "prefix": "YepELzf3Y4lL2",
  "client_id": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "cell_id": "cell-1",
  "scope": "resource.WRITE scope.TEST resource.READ ...",
  "active": true,
  "expires_at": "2026-04-03T13:55:18Z",
  "created_at": "2026-03-20T13:55:18Z",
  "expires_in_seconds": 1209540,
  "source": "INT",
  "env": "D",
  "flow": "CC"
}
```

### Listar todos os tokens

```bash
curl -s "http://localhost:9080/api/oauth/tokens"
```

### Listar tokens filtrado por client_id

```bash
curl -s "http://localhost:9080/api/oauth/tokens?client_id=f8b87b48-3969-4308-9d68-df4d4949c212"
```

---

## 7. Revogar Token

Retorna `200 OK` com body vazio.

```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=token" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "token={TOKEN_OPACO}"
```

**Verificar que o token foi revogado:**
```bash
curl -s -X POST http://localhost:9080/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token={TOKEN_OPACO}"
```
Deve retornar `{"active":false}`

**Exchange com token revogado deve falhar:**
```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "subject_token={TOKEN_OPACO}" \
  -d "resource=urn:ietf:params:oauth:resource:opaque"
```
Deve retornar `{"error":"invalid_grant","error_description":"subject_token has been revoked"}`

---

## 8. Multi-Tenant (Credencial de outra org)

### Gerar token para #APP Parceiros (org diferente)

```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=11111111-2222-3333-4444-555555555555" \
  -d "client_secret=cc2233dd-4455-6677-8899-aabbccddeeff"
```

> Revogar o token do Gateway **nao afeta** o token dos Parceiros (isolamento por org).

---

## 9. Casos de Erro

### Credencial invalida
```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=senha-errada"
```
Retorna: `{"error":"invalid_client","error_description":"invalid client credentials"}`

### Grant type invalido
```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f"
```
Retorna: `{"error":"unsupported_grant_type",...}`

### Client ID inexistente
```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=nao-existe" \
  -d "client_secret=qualquer"
```
Retorna: `{"error":"invalid_client","error_description":"application not found"}`

### Token inexistente na introspecao
```bash
curl -s -X POST http://localhost:9080/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=fake.token.value"
```
Retorna: `{"active":false}`

### Exchange sem subject_token
```bash
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "resource=urn:ietf:params:oauth:resource:opaque"
```
Retorna: `{"error":"invalid_request","error_description":"missing subject_token"}`

---

## Fluxo Completo (copiar e colar)

Script para executar o fluxo completo de uma vez:

```bash
# 1. Gerar token opaco
RESP=$(curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f")
echo "1. Token opaco gerado:"
echo "$RESP"

# Extrair o access_token
TOKEN=$(echo "$RESP" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"//;s/"$//')
echo ""
echo "   access_token=$TOKEN"
echo ""

# 2. Consultar token via GET
echo "2. Consulta do token:"
curl -s "http://localhost:9080/api/oauth/tokens/$TOKEN"
echo ""
echo ""

# 3. Introspecao
echo "3. Introspecao:"
curl -s -X POST http://localhost:9080/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$TOKEN"
echo ""
echo ""

# 4. Token Exchange (opaque -> JWT)
echo "4. Token Exchange (opaque -> JWT):"
curl -s -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "subject_token=$TOKEN" \
  -d "resource=urn:ietf:params:oauth:resource:opaque"
echo ""
echo ""

# 5. Revogar token
echo "5. Revogar token:"
curl -s -o /dev/null -w "HTTP %{http_code}" -X POST http://localhost:9080/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=token" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "token=$TOKEN"
echo ""
echo ""

# 6. Verificar revogacao
echo "6. Token apos revogacao:"
curl -s -X POST http://localhost:9080/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$TOKEN"
echo ""
```
