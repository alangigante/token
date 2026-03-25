# Relatorio de Prova de Conceito (PoC)
## STS Token Opaco com Arquitetura Camada Zero

---

## 1. Introducao

### Objetivo da PoC
Validar a viabilidade tecnica de implementacao de um sistema de **token opaco** no STS (Security Token Service) utilizando a arquitetura **Camada Zero** (Cell-based Architecture) da AWS, garantindo resiliencia, escalabilidade horizontal e roteamento inteligente por prefixo de token.

### Contexto
Atualmente o STS gera apenas tokens JWT. Existe a demanda de suportar **tokens opacos** para cenarios onde o token nao deve carregar informacoes no payload (seguranca por referencia vs seguranca por valor). O token opaco e armazenado no banco de dados e validado via introspeccao online, oferecendo controle total sobre revogacao e tempo de vida.

A decisao entre token opaco ou JWT e feita por **credencial** (campo `token_opaco` no cadastro da aplicacao), mantendo a mesma interface de requisicao para ambos os fluxos.

### Escopo
- Geracao de token opaco e JWT (mesmo endpoint, mesma requisicao)
- Token Exchange (opaco → JWT) para APIs que recebem token opaco
- Revogacao de token opaco no banco de dados
- Introspeccao de token (validacao online via POST e GET)
- Consulta de tokens via GET (detalhe e listagem)
- Roteamento baseado em prefixo do token (Compass Router)
- Arquitetura Cell-based com regra N-1 de capacidade
- Mocks para desenvolvimento local (Cassandra, DynamoDB)

**Fora do escopo:** Integracao com Cassandra/DynamoDB reais, RSA via HSM/KMS, Portal de Credenciais, integracao com Compass Router de producao.

---

## 2. Descricao da Solucao

### 2.1 Tecnologias Utilizadas

| Tecnologia | Finalidade |
|------------|-----------|
| **Go 1.23** | Linguagem principal do STS (alta performance, baixa latencia) |
| **net/http (stdlib)** | HTTP server (sem framework externo, menor superficie de ataque) |
| **crypto/hmac + crypto/rand** | Assinatura JWT (mock HMAC) e geracao de tokens opacos |
| **Docker + Docker Compose** | Containerizacao e orquestracao local |
| **Kubernetes (EKS)** | Manifests para deploy em producao (namespace, HPA, headless services) |
| **Bash + curl** | Scripts de teste automatizados (26 cenarios) |

### 2.2 Arquitetura Proposta

A arquitetura segue o padrao **Cell-based Architecture** (Camada Zero) da AWS:

```
                    +-------------------+
                    |   DNS / Route 53  |
                    +--------+----------+
                             |
                    +--------v----------+
                    |  Compass Router   |   <- Camada mais fina possivel
                    |  (roteamento)     |   <- Roteia por prefixo do token
                    +--+---+---+---+---++
                       |   |   |   |   |
               +-------+ +-+-+ +--++ +--+----+
               |Cell 1 | |C 2| |C 3| |Cell 4 |
               | (STS) | |(S)| |(S)| | (STS) |
               +-------+ +---+ +---+ +-------+
```

**Componentes:**

| Componente | Responsabilidade | Producao |
|------------|-----------------|----------|
| Compass Router | Roteamento thin por prefixo/client/least-loaded | NLB + API Gateway |
| STS Cell | Instancia completa do STS (token lifecycle) | EKS Pod |
| Token Store | Armazenamento de tokens opacos | Cassandra (3 nos, replicacao imediata) |
| App Store | Cadastro de credenciais/aplicacoes | DynamoDB |
| Prefix Mapping | Mapeamento prefix → cell_id | DynamoDB |

**Estrategias de roteamento (Compass Router):**

| Prioridade | Estrategia | Quando |
|------------|-----------|--------|
| 1 | Prefixo do token | Exchange, revoke, introspect |
| 2 | Client ID | Geracao de novo token |
| 3 | Least loaded | Fallback |

### 2.3 Claims do Token

#### Claims do token gerado no STSGo (client_credentials)

```json
{
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "sub": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "exp": 1774288050,
  "iat": 1774279750,
  "Access_Token": "2aa3fe95.2a0abf30-266c-4503-a577-a061e933318e",
  "usr": "null",
  "flow": "CC",
  "source": "INT",
  "site": "ctmm1",
  "env": "p",
  "mbi": "true",
  "aut": "",
  "scope": "appid-8c1244b6-39f7-4a1e-99f6-c7bfe0cd465e biometria-sessao"
}
```

| Claim | Descricao | Exemplo |
|-------|-----------|---------|
| `iss` | Emissor do token (issuer) | `https://openid.itau.com.br/api/oauth/token` |
| `sub` | Subject — ID da credencial (client_id) | `b29c0e84-2d39-4f5c-89f0-29655aab46cf` |
| `exp` | Timestamp de expiracao (Unix epoch) | `1774288050` |
| `iat` | Timestamp de emissao (issued at) | `1774279750` |
| `Access_Token` | Token opaco no formato `prefix.client_id.suffix` | `2aa3fe95.2a0abf30-266c-4503-a577-a061e933318e` |
| `usr` | Usuario associado (null para client_credentials) | `null` |
| `flow` | Fluxo OAuth utilizado | `CC` (client_credentials) |
| `source` | Origem da requisicao | `INT` (interno) / `EXT` (externo) |
| `site` | Site/ambiente de deploy | `ctmm1` |
| `env` | Ambiente | `p` (producao), `D` (dev), `H` (homolog) |
| `mbi` | Flag MBI | `true` |
| `aut` | Tipo de autenticacao | (vazio para client_credentials) |
| `scope` | Escopos autorizados | `appid-8c1244b6-... biometria-sessao` |

#### Formato do Access Token (opaco)

```
2aa3fe95 . 2a0abf30-266c-4503-a577-a061e933318e . DkqvRS7a73LYIkb
|________|   |___________________________________|   |_______________|
  PREFIX              CLIENT_ID (UUID)                   SUFFIX
 (routing)        (identifica credencial)           (unicidade)
```

- **Prefix**: Identificador aleatorio usado pelo Compass Router para rotear a requisicao para o cell/shard correto
- **Client ID**: UUID da credencial que gerou o token
- **Suffix**: String aleatoria para garantir unicidade do token

#### Resposta da validacao/introspeccao do token (STSGo)

```json
{
  "Access_Token": "2aa3fe95.2a0abf30-266c-4503-a577-a061e933318e",
  "active": true,
  "client_id": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "env": "p",
  "exp": 1774288050000,
  "flow": "CC",
  "iat": 1774279750000,
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "mbi": "true",
  "scope": "appid-8c1244b6-39f7-4a1e-99f6-c7bfe0cd465e biometria-sessao",
  "site": "ctmm1",
  "source": "INT",
  "sub": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "user_id": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "username": "null"
}
```

| Claim | Descricao | Diferenca da geracao |
|-------|-----------|---------------------|
| `active` | Se o token esta ativo ou revogado | Presente apenas na introspeccao |
| `client_id` | ID da credencial | Adicionado explicitamente |
| `user_id` | ID do usuario (igual ao sub para CC) | Adicionado explicitamente |
| `username` | Nome do usuario | `null` para client_credentials |
| `exp` / `iat` | Timestamps em **milissegundos** na introspeccao | Na geracao sao em segundos |

### 2.4 Funcionalidades Implementadas

| # | Funcionalidade | Endpoint | Descricao |
|---|---------------|----------|-----------|
| 1 | Geracao de token opaco | `POST /api/oauth/token` | `grant_type=client_credentials` com `token_opaco=true` |
| 2 | Geracao de token JWT | `POST /api/oauth/token` | `grant_type=client_credentials` com `token_opaco=false` |
| 3 | Token Exchange | `POST /api/oauth/token` | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` |
| 4 | Revogacao | `POST /api/oauth/token` | `grant_type=token` |
| 5 | Introspeccao POST | `POST /api/oauth/token_info` | RFC 7662 |
| 6 | Introspeccao GET | `GET /api/oauth/tokeninfo?token=` | Query param |
| 7 | Consulta de token | `GET /api/oauth/tokens/{token}` | Detalhe completo |
| 8 | Listagem de tokens | `GET /api/oauth/tokens[?client_id=]` | Com filtro opcional |
| 9 | Roteamento por prefixo | Compass Router | Prefix → Cell mapping |
| 10 | Auto-detect de cell | `go run ./cmd/cell` | Cell ID e porta automaticos |

### 2.5 Cadastro da Credencial (Application)

O campo `token_opaco` no cadastro da aplicacao determina qual tipo de token sera gerado:

```json
{
  "id": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "name": "#APP Gateway",
  "description": "Aplicacao exclusiva para uso do gateway",
  "organizationId": "afe06c9c-33d7-41c1-932b-91972e5fa730",
  "email": "gateway@example.com",
  "enabled": true,
  "state": "approved",
  "token_opaco": true,
  "usar_revoke": false,
  "req_certificado": false,
  "aplica_rsa": false,
  "provider": "AD",
  "req_flowId": false
}
```

| Campo | Impacto |
|-------|---------|
| `token_opaco: true` | Gera token opaco (`prefix.client_id.suffix`) |
| `token_opaco: false` | Gera token JWT (`eyJ...`) |
| `usar_revoke: true` | Habilita revogacao do token |
| `aplica_rsa: true` | Usa chaves RSA para assinatura JWT |
| `provider` | Provedor de identidade (`AD`, `LDAP`) |
| `state: approved` | Credencial ativa e aprovada |

---

## 3. Metodologia

### 3.1 Como a PoC foi Conduzida

| Etapa | Descricao | Duracao |
|-------|-----------|---------|
| Pesquisa | Estudo da arquitetura Cell-based (AWS Well-Architected) e RFC 7662/7009 | - |
| Modelagem | Definicao de models, interfaces e fluxos OAuth | - |
| Implementacao | Desenvolvimento em Go (router, cell, token service, mock stores) | - |
| Testes | Script automatizado com 26 cenarios cobrindo todos os fluxos | - |
| Documentacao | ARCHITECTURE.md, CURLS.md, RELATORIO_POC.md | - |

### 3.2 Criterios de Sucesso

| Criterio | Resultado | Status |
|----------|----------|--------|
| Gerar token opaco no formato `prefix.client_id.suffix` | Token gerado corretamente | OK |
| Mesma requisicao gera opaco OU JWT conforme credencial | Funciona baseado em `token_opaco` | OK |
| Token exchange retorna JWT valido a partir de token opaco | JWT com claims corretos | OK |
| Revogacao invalida o token no banco | Token passa a `active=false` | OK |
| Introspeccao retorna `active: true/false` | Conforme RFC 7662 | OK |
| Router encaminha por prefixo do token | Prefix mapping funcional | OK |
| Failover: celula down redireciona para outra | Redistribuicao automatica | OK |
| Regra N-1: 4 celulas a 75%, 3 absorvem 100% | Calculo correto | OK |
| Exchange com token revogado e rejeitado | Retorna `invalid_grant` | OK |
| Isolamento: revogacao de uma org nao afeta outra | Confirmado | OK |
| Auto-detect de cell ID e porta | Funciona sem env vars | OK |
| Script de teste sem dependencia de Python | Roda com bash+curl puro | OK |

---

## 4. Resultados

### 4.1 Demonstracao dos Fluxos

#### Fluxo 1: Geracao de Token Opaco

**Requisicao** (identica a de JWT):
```bash
curl -X POST http://localhost:9080/api/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f"
```

**Resposta:**
```json
{
  "sub": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "access_token": "GNIqMR1ihT2zt.f8b87b48-3969-4308-9d68-df4d4949c212._dfSDq_19W4wSxPOZBZQ9",
  "expires_in": "1209600",
  "source": "INT",
  "env": "D",
  "site": "dev",
  "flow": "CC"
}
```

#### Fluxo 2: Token Exchange (Opaque → JWT)

```bash
curl -X POST http://localhost:9080/api/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=f8b87b48-3969-4308-9d68-df4d4949c212" \
  -d "client_secret=ea0abbaa-841a-461f-8981-c310dc1def5f" \
  -d "subject_token={TOKEN_OPACO}" \
  -d "resource=urn:ietf:params:oauth:resource:opaque"
```

**Resposta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1209600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "resource.WRITE scope.TEST resource.READ example_restrito.write rsa.GATEWAY_PUBLIC_KEY",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "active": true
}
```

**JWT decodificado (payload):**
```json
{
  "sub": "f8b87b48-3969-4308-9d68-df4d4949c212",
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "iat": 1774029318,
  "exp": 1775238918,
  "scope": "resource.WRITE scope.TEST resource.READ example_restrito.write rsa.GATEWAY_PUBLIC_KEY",
  "cell_id": "cell-1",
  "env": "D",
  "source": "INT"
}
```

#### Fluxo completo (diagrama de sequencia)

```
Cliente                STS (Compass Router + Cell)           API (Resource Provider)
  |                              |                                    |
  | 1. POST /api/oauth/token    |                                    |
  |   grant_type=client_creds   |                                    |
  |----------------------------->                                     |
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

### 4.2 Tokens Reais do STSGo (Ambiente de Producao)

Os tokens abaixo foram extraidos do STSGo real em ambiente de producao para servir como referencia de implementacao.

#### Token Opaco Gerado (STSGo - Producao)

**Requisicao:**
```bash
curl -X POST https://10.54.192.109:8088/api/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=b29c0e84-2d39-4f5c-89f0-29655aab46cf" \
  -d "client_secret=****"
```

**Resposta (claims do STSGo):**
```json
{
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "sub": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "exp": 1774288050,
  "iat": 1774279750,
  "Access_Token": "2aa3fe95.2a0abf30-266c-4503-a577-a061e93331e",
  "usr": "null",
  "flow": "CC",
  "source": "INT",
  "site": "ctmm1",
  "env": "p",
  "mbi": "true",
  "aut": "",
  "scope": "appid-8c1244b6-39f7-4a1e-99f6-c7bfe0cd465e biometria-sessao"
}
```

**Analise do token gerado:**
```
2aa3fe95 . 2a0abf30-266c-4503-a577-a061e93331e
|________|   |___________________________________|
  PREFIX              CLIENT_ID (UUID)
 (routing)        (identifica credencial)
```

- **Prefix `2aa3fe95`**: Usado pelo Compass Router para direcionar a requisicao ao shard/cell correto
- **Client ID `2a0abf30-266c-4503-a577-a061e93331e`**: UUID da credencial que gerou o token
- **exp - iat = 8300 segundos (~2.3 horas)**: TTL do token em producao
- **env `p`**: Ambiente de producao
- **site `ctmm1`**: Site de deploy especifico

#### Introspeccao do Token (STSGo - Producao)

**Requisicao:**
```bash
curl -X POST https://10.54.192.109:8088/api/oauth/token_info \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=2aa3fe95.2a0abf30-266c-4503-a577-a061e93331e"
```

**Resposta (validacao/introspeccao):**
```json
{
  "Access_Token": "2aa3fe95.2a0abf30-266c-4503-a577-a061e93331e",
  "active": true,
  "client_id": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "env": "p",
  "exp": 1774288050000,
  "flow": "CC",
  "iat": 1774279750000,
  "iss": "https://openid.itau.com.br/api/oauth/token",
  "mbi": "true",
  "scope": "appid-8c1244b6-39f7-4a1e-99f6-c7bfe0cd465e biometria-sessao",
  "site": "ctmm1",
  "source": "INT",
  "sub": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "user_id": "b29c0e84-2d39-4f5c-89f0-29655aab46cf",
  "username": "null"
}
```

#### Comparativo: Geracao vs Introspeccao (STSGo Real)

| Claim | Geracao | Introspeccao | Observacao |
|-------|---------|-------------|-----------|
| `iss` | `https://openid.itau.com.br/api/oauth/token` | `https://openid.itau.com.br/api/oauth/token` | Igual |
| `sub` | `b29c0e84-2d39-4f5c-89f0-29655aab46cf` | `b29c0e84-2d39-4f5c-89f0-29655aab46cf` | Igual |
| `exp` | `1774288050` (segundos) | `1774288050000` (**milissegundos**) | **Atencao: unidade diferente** |
| `iat` | `1774279750` (segundos) | `1774279750000` (**milissegundos**) | **Atencao: unidade diferente** |
| `Access_Token` | `2aa3fe95.2a0abf30-...` | `2aa3fe95.2a0abf30-...` | Igual |
| `usr` | `"null"` | - | Ausente na introspeccao |
| `flow` | `"CC"` | `"CC"` | Igual |
| `source` | `"INT"` | `"INT"` | Igual |
| `site` | `"ctmm1"` | `"ctmm1"` | Igual |
| `env` | `"p"` | `"p"` | Igual |
| `mbi` | `"true"` | `"true"` | Igual |
| `aut` | `""` | - | Ausente na introspeccao |
| `scope` | `"appid-8c1244b6-... biometria-sessao"` | `"appid-8c1244b6-... biometria-sessao"` | Igual |
| `active` | - | `true` | **Presente apenas na introspeccao** |
| `client_id` | - | `b29c0e84-2d39-...` | **Presente apenas na introspeccao** |
| `user_id` | - | `b29c0e84-2d39-...` | **Presente apenas na introspeccao** (igual ao sub para CC) |
| `username` | - | `"null"` | **Presente apenas na introspeccao** |

#### Comparativo: Token STSGo Real vs PoC

| Aspecto | STSGo Real (Producao) | PoC (Local) |
|---------|----------------------|-------------|
| **Token format** | `2aa3fe95.2a0abf30-266c-...` | `GNIqMR1ihT2zt.f8b87b48-3969-...._dfSDq_19W4wSxPOZBZQ9` |
| **Prefix length** | 8 chars | 13 chars |
| **Suffix** | Nao visivel (2 partes) | 21 chars (3 partes) |
| **TTL** | ~2.3 horas (prod) | 14 dias (1209600s) |
| **exp/iat geracao** | Segundos | Segundos (string) |
| **exp/iat introspeccao** | Milissegundos | Segundos (int) |
| **iss** | `https://openid.itau.com.br/api/oauth/token` | `https://openid.itau.com.br/api/oauth/token` |
| **env** | `p` (producao) | `D` (dev) |
| **site** | `ctmm1` | `dev` |
| **mbi** | `"true"` | Nao implementado |
| **aut** | `""` | Nao implementado |
| **Armazenamento** | Cassandra (3 nos) | In-memory (mock) |
| **Assinatura JWT** | RSA (HSM/KMS) | HMAC-SHA256 (mock) |

> **Nota**: Os campos `mbi` e `aut` nao foram implementados na PoC pois sao especificos do ambiente de producao. Podem ser adicionados facilmente ao modelo `OpaqueToken` e `OpaqueTokenResponse` quando necessario.

### 4.3 Cobertura de Testes (26 cenarios)

| # | Cenario | Resultado |
|---|---------|----------|
| 1 | Health check do router | PASS |
| 2 | Health check direto da cell | PASS |
| 3 | Listagem de cells registradas | PASS |
| 4 | Router info endpoint | PASS |
| 5 | Gerar token opaco (token_opaco=true) | PASS |
| 6 | Consultar token via GET | PASS |
| 7 | Listar tokens | PASS |
| 8 | Gerar token JWT (token_opaco=false) | PASS |
| 9 | Introspeccao POST (token_info) | PASS |
| 10 | Introspeccao GET (tokeninfo) | PASS |
| 11 | Token Exchange (opaque → JWT) | PASS |
| 12 | Token opaco com segunda credencial (outra org) | PASS |
| 13 | Listar tokens filtrado por client_id | PASS |
| 14 | Introspect token parceiros | PASS |
| 15 | Revogar token opaco | PASS |
| 16 | Verificar token revogado esta inativo | PASS |
| 17 | GET token revogado - verificar status | PASS |
| 18 | Exchange com token revogado deve falhar | PASS |
| 19 | Credencial invalida rejeitada | PASS |
| 20 | Grant type invalido rejeitado | PASS |
| 21 | Client ID inexistente rejeitado | PASS |
| 22 | Introspect com token inexistente retorna inactive | PASS |
| 23 | Exchange sem subject_token rejeitado | PASS |
| 24 | Revoke sem token rejeitado | PASS |
| 25 | Token parceiros ainda ativo apos revogar Gateway | PASS |
| 26 | Listagem final de tokens | PASS |

**Resultado: 26/26 testes passaram.**

### 4.3 Desempenho da Arquitetura Camada Zero

| Metrica | Valor |
|---------|-------|
| Celulas na PoC | 4 |
| Capacidade por celula (normal) | 75% (regra N-1) |
| Capacidade com 1 celula down | 100% (3 celulas absorvem) |
| Blast radius (1 celula falha) | 25% dos tenants (isolamento) |
| Tempo de failover | < 30s (health check interval) |
| Roteamento por prefixo | O(1) lookup na tabela de mapeamento |

### 4.4 Problemas Encontrados e Limitacoes

| Problema | Solucao |
|----------|---------|
| Porta 8080 conflitava com aplicacao Java existente | Alterado para portas 9080-9084 |
| `python3` no Windows abre Microsoft Store | Removida dependencia de Python, script usa bash puro |
| WSL intercepta comando `bash` no Windows | Documentado uso de Git Bash com caminho completo |
| Tokens opacos ficam na memoria (mock) | Em producao usar Cassandra com 3 nos replicados |
| JWT assinado com HMAC (mock) | Em producao usar RSA via HSM/KMS |
| Mapeamento prefix → cell perdido ao reiniciar router | Em producao usar DynamoDB persistente |

### 4.5 Licoes Aprendidas

1. **Mesma interface, decisao interna**: Manter a mesma requisicao para token opaco e JWT simplifica a integracao dos clientes. A decisao e feita pelo servidor com base no cadastro da credencial (`token_opaco`).

2. **Prefixo como chave de roteamento**: O prefixo do token opaco funciona como partition key natural para o Compass Router, eliminando a necessidade de lookup no banco para roteamento.

3. **Isolamento por celula**: A arquitetura cell-based garante que uma falha em uma celula nao propaga para as demais. Tokens de uma org nao sao afetados por revogacao de outra.

4. **Token Exchange como ponte**: O exchange (opaco → JWT) permite que APIs internas trabalhem com JWT mesmo quando o cliente usa token opaco, mantendo a flexibilidade da arquitetura.

---

## 5. Conclusao

### 5.1 Avaliacao de Viabilidade Tecnica

A PoC demonstrou que e **tecnicamente viavel** implementar token opaco no STS com arquitetura Camada Zero. Os principais pontos validados:

- O formato `prefix.client_id.suffix` funciona para roteamento sem lookup adicional
- A mesma interface de requisicao para token opaco e JWT simplifica o consumo
- O token exchange (opaco → JWT) e transparente para as APIs
- A arquitetura cell-based garante resiliencia com a regra N-1
- A revogacao e imediata e isolada por credencial/organizacao
- O sistema funciona com zero dependencias externas (Go stdlib puro)

### 5.2 Recomendacoes para Proximos Passos

| Prioridade | Acao | Descricao |
|------------|------|-----------|
| Alta | Integracao com Cassandra | Substituir mock por Cassandra real (3 nos, replicacao imediata) |
| Alta | Chaves RSA via KMS | Substituir HMAC por RSA com chaves gerenciadas pelo KMS/HSM |
| Alta | Portal de Credenciais | Adicionar campo `token_opaco` no cadastro de credenciais |
| Media | Integracao Compass | Configurar roteamento por prefixo no Compass Router real |
| Media | Testes de carga | Validar throughput e latencia sob carga com 4 celulas |
| Media | Migracao de tokens no failover | Definir estrategia para tokens opacos quando celula cai (re-auth vs replicacao) |
| Baixa | Metricas e observabilidade | Instrumentar com Prometheus/Grafana por celula |
| Baixa | Canary deployment | Deploy progressivo entre celulas (cell-1 primeiro, depois demais) |

---

## 6. Anexos

### 6.1 Estrutura do Projeto

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
      token.go               # Logica de geracao, exchange, revogacao, introspeccao
    router/router.go         # Logica de roteamento (prefix, client, least-loaded)
  pkg/models/models.go       # Modelos de dados (Application, OpaqueToken, etc.)
  k8s/                       # Manifests Kubernetes (namespace, deployments, HPA)
  scripts/test-local.sh      # Script de testes (26 cenarios, bash puro)
  docker-compose.yml         # Docker Compose (1 router + 4 cells)
  Dockerfile                 # Multi-stage build
  ARCHITECTURE.md            # Documentacao de arquitetura
  CURLS.md                   # Guia de curls para todos os fluxos
  RELATORIO_POC.md           # Este relatorio
```

### 6.2 Como Executar

```bash
# Terminal 1: Router
go run ./cmd/router

# Terminal 2: Cell (auto-detecta ID e porta)
go run ./cmd/cell

# Terminal 3: Outra cell (auto-detecta automaticamente)
go run ./cmd/cell

# Terminal 4: Rodar testes
"C:\Program Files\Git\bin\bash.exe" scripts/test-local.sh
```

### 6.3 Comparativo: Token Opaco vs JWT

| Aspecto | Token Opaco | Token JWT |
|---------|------------|-----------|
| Formato | `prefix.client_id.suffix` | `eyJhbG...` (Base64) |
| Informacao no token | Nenhuma (referencia) | Claims no payload |
| Validacao | Online (introspeccao no STS) | Offline (verificacao de assinatura) |
| Revogacao | Imediata (deleta do banco) | Dificil (espera expirar ou blacklist) |
| Tamanho | ~80 caracteres | ~500+ caracteres |
| Seguranca | Claims nao expostos ao cliente | Claims visiveis (mesmo assinados) |
| Latencia de validacao | +1 chamada ao STS | Zero (validacao local) |
| Uso recomendado | APIs externas, alta seguranca | APIs internas, microservicos |

### 6.4 Comparativo: Claims Geracao vs Introspeccao

| Claim | Geracao | Introspeccao | Observacao |
|-------|---------|-------------|-----------|
| `iss` | Presente | Presente | Igual |
| `sub` | Presente | Presente | Igual |
| `exp` | Segundos | **Milissegundos** | Atencao na conversao |
| `iat` | Segundos | **Milissegundos** | Atencao na conversao |
| `Access_Token` | Presente | Presente | Igual |
| `active` | Ausente | **Presente** | So na introspeccao |
| `client_id` | Ausente | **Presente** | So na introspeccao |
| `user_id` | Ausente | **Presente** | Igual ao `sub` para CC |
| `username` | Ausente | **Presente** | `null` para CC |
| `flow` | Presente | Presente | `CC` |
| `source` | Presente | Presente | `INT` / `EXT` |
| `env` | Presente | Presente | `p`, `D`, `H` |
| `site` | Presente | Presente | `ctmm1`, `dev` |
| `mbi` | Presente | Presente | `true` / `false` |
| `scope` | Presente | Presente | Igual |
