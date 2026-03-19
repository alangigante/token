# STS OAuth 2.0 Token Opaco - Arquitetura Camada Zero

## Visao Geral

PoC de um Security Token Service (STS) com suporte a **token opaco** e **token JWT**, usando a arquitetura **Camada Zero** (Cell-based Architecture) da AWS.

A arquitetura garante que, com N celulas, cada uma opera a `(N-1)/N` de capacidade. Se uma celula falhar, as restantes absorvem 100% da carga sem degradacao.

```
                    +------------------+
                    |    DNS / LB      |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Compass Router  |   <-- Camada mais fina possivel
                    |  (roteamento)    |   <-- Roteia por prefixo do token
                    +--+----+----+---+-+
                       |    |    |   |
               +-------+  ++-+  +-+ +-------+
               | Cell 1|  |C 2|  |C3| |Cell 4|
               | (STS) |  |(S)|  |(S)| | (STS)|
               +-------+  +---+  +--+ +------+
```

## Componentes

### 1. Compass Router (`cmd/router`)

Camada de roteamento thin que fica na frente das celulas. Nao processa logica de negocio.

**Estrategias de roteamento (em ordem de prioridade):**

| Prioridade | Estrategia | Quando usar |
|------------|-----------|-------------|
| 1 | Prefixo do token | Exchange, revoke, introspect (token ja existe) |
| 2 | Client ID | Geracao de novo token (client_credentials) |
| 3 | Least loaded | Fallback quando nenhum mapeamento existe |

**Endpoints:**

| Metodo | Path | Descricao |
|--------|------|-----------|
| POST | `/api/oauth/token` | Gerar token / Exchange / Revoke (proxy) |
| POST | `/api/oauth/token_info` | Introspecao POST (proxy) |
| GET | `/api/oauth/tokeninfo` | Introspecao GET (proxy) |
| GET | `/api/oauth/tokens` | Listar tokens (proxy) |
| GET | `/api/oauth/tokens/{token}` | Detalhe do token (proxy) |
| GET | `/cells` | Listar celulas registradas |
| POST | `/cells/register` | Registrar nova celula |
| GET | `/health` | Health check do router |

### 2. STS Cell (`cmd/cell`)

Cada celula e uma instancia completa e independente do STS. Contem:
- Token store (mock in-memory, prod: Cassandra com 3 nos replicados)
- Application store (mock in-memory, prod: DynamoDB)
- Servico de geracao/validacao de tokens
- Assinatura JWT (mock HMAC, prod: RSA via HSM/KMS)

### 3. Mock Stores (`internal/mock`)

| Store | Simula | Producao |
|-------|--------|----------|
| `TokenStore` | Cassandra (replicacao imediata entre nos) | Cassandra 3 nos |
| `ApplicationStore` | Portal de Credenciais / DynamoDB | DynamoDB |
| `TenantCellMapping` | Tabela de roteamento org->cell | DynamoDB |
| `PrefixCellMapping` | Tabela de roteamento prefix->cell | DynamoDB |

## Fluxos OAuth 2.0

### Fluxo 1: Geracao de Token Opaco (`token_opaco=true`)

A credencial (Application) tem o campo `token_opaco: true`. A requisicao e **identica** a de token JWT.

```
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
client_id=f8b87b48-3969-4308-9d68-df4d4949c212
client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f
```

**Resposta (token opaco):**
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

**Formato do token:** `{prefix}.{client_id}.{suffix}`

- **prefix** (13 chars): Usado pelo Compass Router para rotear para a celula correta
- **client_id**: UUID da credencial
- **suffix** (21 chars): Random para unicidade

O token e salvo no banco de dados (Cassandra) com replicacao imediata entre os nos.

### Fluxo 2: Geracao de Token JWT (`token_opaco=false`)

Mesma requisicao, mas a credencial tem `token_opaco: false`. O servidor decide automaticamente.

**Resposta (JWT):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...",
  "token_type": "Bearer",
  "expires_in": 1209600,
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "scope": "resource.READ resource.WRITE"
}
```

### Fluxo 3: Token Exchange (Opaque -> JWT)

Quando uma API recebe um token opaco, ela faz exchange no STS para obter um JWT.

```
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
client_id=f8b87b48-3969-4308-9d68-df4d4949c212
client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f
subject_token=YepELzf3Y4lL2.f8b87b48-3969-4308-9d68-df4d4949c212.gtkUHb19hZOFE
resource=urn:ietf:params:oauth:resource:opaque
```

**Resposta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1209600,
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "scope": "resource.WRITE scope.TEST resource.READ",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "active": true
}
```

**Diagrama do fluxo completo:**

```
Cliente                STS (Compass Router + Cell)           API (Resource Provider)
  |                              |                                    |
  | 1. POST /api/oauth/token    |                                    |
  |   grant_type=client_creds   |                                    |
  |----------------------------->                                    |
  |                              |                                    |
  | 2. Retorna token opaco      |                                    |
  |   {prefix}.{client}.{rand}  |                                    |
  |<-----------------------------|                                    |
  |                              |                                    |
  | 3. Chama API com token opaco (Authorization: Bearer {opaque})    |
  |----------------------------------------------------------------->|
  |                              |                                    |
  |                              | 4. Token exchange (opaque -> JWT)  |
  |                              |   grant_type=token-exchange        |
  |                              |   subject_token={opaque}           |
  |                              |<-----------------------------------|
  |                              |                                    |
  |                              | 5. Retorna JWT                     |
  |                              |----------------------------------->|
  |                              |                                    |
  |                                        6. Resposta do recurso    |
  |<-----------------------------------------------------------------|
```

### Fluxo 4: Introspecao de Token

Validacao online se o token esta ativo.

**POST (token_info):**
```
POST /api/oauth/token_info
token=YepELzf3Y4lL2.f8b87b48-3969-4308-9d68-df4d4949c212.DkqvRS7a73LYIkbIBmnyF
```

**GET (tokeninfo):**
```
GET /api/oauth/tokeninfo?token=YepELzf3Y4lL2...
```

**Resposta:**
```json
{
  "active": true,
  "scope": "resource.WRITE scope.TEST resource.READ",
  "client_id": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "token_type": "opaque",
  "cell_id": "cell-1",
  "source": "INT",
  "env": "D",
  "flow": "CC"
}
```

### Fluxo 5: Revogacao de Token

```
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=token
client_id=f8b87b48-3969-4308-9d68-df4d4949c212
client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f
token=YepELzf3Y4lL2.f8b87b48-3969-4308-9d68-df4d4949c212.DkqvRS7a73LYIkbIBmnyF
```

Retorna `200 OK` com body vazio.

### Fluxo 6: Consulta de Token (GET)

**Detalhe de um token especifico:**
```
GET /api/oauth/tokens/{access_token}
```

**Listar todos os tokens (opcionalmente filtrado por client_id):**
```
GET /api/oauth/tokens
GET /api/oauth/tokens?client_id=f8b87b48-3969-4308-9d68-df4d4949c212
```

## Regra N-1 (Capacidade)

Com 4 celulas:

| Estado | Capacidade por celula | Total |
|--------|----------------------|-------|
| Normal (4 cells) | 75% cada | 100% |
| 1 cell down (3 cells) | 100% cada | 100% |
| 2 cells down (2 cells) | 100% cada | ~67% (degradado) |

O HPA do Kubernetes monitora CPU/memoria a 75% e escala automaticamente.

## Cadastro de Credenciais (Application)

O campo `token_opaco` na credencial determina o tipo de token:

```json
{
  "id": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "name": "#APP Gateway",
  "organizationId": "afe06c9c-33d7-41c1-932b-91972e5fa730",
  "enabled": true,
  "state": "approved",
  "token_opaco": true,
  "usar_revoke": false,
  "aplica_rsa": false,
  "provider": "AD"
}
```

| Campo | Descricao |
|-------|-----------|
| `token_opaco: true` | Gera token opaco no formato `prefix.client_id.suffix` |
| `token_opaco: false` | Gera token JWT padrao |
| `usar_revoke` | Habilita revogacao do token |
| `aplica_rsa` | Usa chaves RSA para assinatura JWT |
| `provider` | Provedor de identidade (AD, LDAP) |

## Como Rodar Localmente

### Sem Docker

```bash
# Terminal 1: Compass Router
PORT=9080 go run ./cmd/router

# Terminal 2: Cell 1
CELL_ID=cell-1 PORT=9081 ROUTER_ADDR=localhost:9080 go run ./cmd/cell

# Terminal 3: Cell 2 (opcional)
CELL_ID=cell-2 PORT=9082 ROUTER_ADDR=localhost:9080 go run ./cmd/cell

# Terminal 4: Rodar testes
bash scripts/test-local.sh
```

### Com Docker Compose

```bash
docker-compose up --build
```

Sobe 1 router (porta 9080) + 4 cells (portas 9081-9084).

### Kubernetes (EKS)

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/router-deployment.yaml
kubectl apply -f k8s/cell-deployment.yaml
kubectl apply -f k8s/cell-hpa.yaml
```

## Cobertura de Testes (`scripts/test-local.sh`)

O script de testes cobre 26 cenarios:

1. Health check do router e cell
2. Listagem de celulas registradas
3. Geracao de token opaco (`token_opaco=true`)
4. Consulta de token via GET
5. Listagem de tokens com filtro por client_id
6. Geracao de token JWT (`token_opaco=false`)
7. Introspecao POST e GET
8. Token exchange (opaque -> JWT) + decode do payload
9. Multi-tenant (credenciais de orgs diferentes)
10. Revogacao de token + verificacao de inatividade
11. Exchange rejeitado apos revogacao
12. Isolamento entre orgs (revogacao nao afeta outras)
13. Casos de erro (credencial invalida, grant invalido, client inexistente)

## Estrutura do Projeto

```
poc/
  cmd/
    router/main.go          # Compass Router (camada de roteamento)
    cell/main.go             # STS Cell (instancia do servico)
  internal/
    cell/manager.go          # Gerenciamento de celulas e health checks
    mock/store.go            # Stores in-memory (Cassandra, DynamoDB mocks)
    oauth/
      server.go              # HTTP handlers para todos os fluxos OAuth
      token.go               # Logica de geracao, exchange, revogacao, introspecao
    router/router.go         # Logica de roteamento (prefix, client, least-loaded)
  pkg/models/models.go       # Modelos de dados (Application, OpaqueToken, etc.)
  k8s/                       # Manifests Kubernetes (namespace, deployments, HPA)
  scripts/test-local.sh      # Script de testes com 26 cenarios
  docker-compose.yml         # Docker Compose (1 router + 4 cells)
  Dockerfile                 # Multi-stage build
  ARCHITECTURE.md            # Este arquivo
```

## Decisoes de Producao (Pontos em Aberto)

| Questao | Opcoes |
|---------|--------|
| Cadastro de credenciais no DynamoDB | Ajuste no Portal de Credenciais para incluir `token_opaco` |
| Novas credenciais com token opaco | Definir processo de aprovacao e cadastro |
| Direcionamento no Compass (JWT vs opaque) | Shards dedicados por tipo de cliente, ou roteamento por prefixo |
| Replicacao de tokens entre cells | Cassandra Global Tables ou forcar re-auth no failover |
| Chaves RSA para JWT | HSM/KMS por cell ou chave compartilhada via Secrets Manager |
