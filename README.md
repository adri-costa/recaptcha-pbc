# reCAPTCHA Enterprise - Policy-Based Challenge

Aplicação Java Spring Boot de referência para uso de chave reCAPTCHA Enterprise com Policy-Based Challenge.

## Objetivo

Demonstrar uma integração segura e objetiva entre uma aplicação web e o reCAPTCHA Enterprise usando Policy-Based Challenge.

Este projeto cobre o fluxo mínimo recomendado para uma aplicação validar se a interação do usuário deve ser permitida, bloqueada ou tratada como erro técnico.

## Demonstrado neste projeto

- Integração da chave pública com o navegador.
- Geração do token no frontend.
- Criação do assessment no backend.
- Validação de `action`, validade do token, hostname e challenge.
- Uso opcional de annotation no assessment.
- Separação entre decisão do reCAPTCHA e autenticação real da aplicação.

## Pré-requisitos

- Java 17.
- Maven 3.9+.
- Projeto na GCP com reCAPTCHA Enterprise habilitado.
- Site key criada com Policy-Based Challenge.
- API key criada para uso no backend.

## Variáveis de ambiente

### PowerShell

```powershell
$env:RECAPTCHA_PROJECT_ID="your-gcp-project-id"
$env:RECAPTCHA_SITE_KEY="your-public-site-key"
$env:RECAPTCHA_API_KEY="your-backend-api-key"
$env:RECAPTCHA_EXPECTED_HOSTNAME="localhost"
$env:RECAPTCHA_TIMEOUT_MS="3000"
$env:RECAPTCHA_TRUST_PROXY_HEADERS="false"
$env:RECAPTCHA_ANNOTATIONS_ENABLED="false"
```

### Linux/macOS

```bash
export RECAPTCHA_PROJECT_ID="your-gcp-project-id"
export RECAPTCHA_SITE_KEY="your-public-site-key"
export RECAPTCHA_API_KEY="your-backend-api-key"
export RECAPTCHA_EXPECTED_HOSTNAME="localhost"
export RECAPTCHA_TIMEOUT_MS="3000"
export RECAPTCHA_TRUST_PROXY_HEADERS="false"
export RECAPTCHA_ANNOTATIONS_ENABLED="false"
```

## Observações sobre as variáveis

- `RECAPTCHA_SITE_KEY` é pública e pode ser exposta no navegador.
- `RECAPTCHA_API_KEY` deve ficar somente no backend.
- `RECAPTCHA_API_KEY` deve ter restrições adequadas no Google Cloud.
- `RECAPTCHA_EXPECTED_HOSTNAME` é opcional, mas recomendado quando se sabe o hostname esperado.
- `RECAPTCHA_TRUST_PROXY_HEADERS` deve ficar `false`, exceto quando a aplicação estiver atrás de um proxy confiável.
- `RECAPTCHA_ANNOTATIONS_ENABLED` deve ficar `false` por padrão e ser habilitada apenas quando o processo de annotation estiver definido.

## Execução local

```powershell
mvn spring-boot:run
```

Acesse:

```text
http://localhost:8080
```

## Execução de testes

```powershell
mvn test
```

## Decisões da aplicação

### ALLOW

A requisição pode seguir para a autenticação real da aplicação.

Condições mínimas:

- token válido;
- action retornada igual à action esperada;
- hostname compatível, quando configurado;
- challenge diferente de `FAIL`.

Importante: `ALLOW` não significa usuário autenticado. A aplicação ainda precisa validar usuário, senha, MFA, sessão e demais controles.

### DENY

A requisição deve ser bloqueada.

Exemplos:

- token ausente;
- token inválido;
- action divergente;
- hostname divergente;
- challenge com valor `FAIL`.

### ERROR

A aplicação não conseguiu validar o reCAPTCHA por erro técnico.

Exemplos:

- indisponibilidade temporária da API;
- timeout;
- falha de comunicação;
- erro inesperado na criação do assessment.

Neste caso, a aplicação deve aplicar a estratégia definida pela área de segurança e pelo negócio.

## Motivos de decisão

O projeto separa dois conceitos:

### `invalidReason`

Motivo retornado pelo próprio reCAPTCHA para o token.

### `decisionReason`

Motivo interno da aplicação para permitir, negar ou tratar como erro.

Exemplos de `decisionReason`:

- `MISSING_TOKEN`
- `TOKEN_INVALID`
- `ACTION_MISMATCH`
- `HOSTNAME_MISMATCH`
- `CHALLENGE_FAILED`
- `VALID_RECAPTCHA_ASSESSMENT`
- `RECAPTCHA_UNAVAILABLE`

## Notas de segurança

- Não autentique o usuário apenas porque o reCAPTCHA retornou `ALLOW`.
- Crie o assessment dentro do prazo de validade do token.
- Valide sempre a `action` retornada pelo assessment.
- Valide o hostname quando a aplicação souber o hostname esperado.
- Apenas confie em `X-Forwarded-For` ou `X-Real-IP` quando a aplicação estiver atrás de proxy confiável.
- Não exponha a API key no frontend.
- Não registre token, senha ou dados sensíveis em log.
- Mantenha timeout baixo para evitar travamento do fluxo de autenticação.
- Use annotation somente após a aplicação conhecer o desfecho real da ação, por exemplo login legítimo confirmado ou tentativa fraudulenta confirmada.

## Annotation

A annotation é opcional e controlada por configuração:

```yaml
recaptcha:
  annotations-enabled: false
```

Quando habilitada, a aplicação pode enviar feedback ao reCAPTCHA após conhecer o resultado real da ação.

Exemplos:

- `LEGITIMATE`: quando a ação foi confirmada como legítima.
- `FRAUDULENT`: quando a ação foi confirmada como fraudulenta.

Não use annotation apenas porque o score foi baixo. O ideal é anotar com base no resultado real observado pela aplicação.

## Fluxo resumido

```text
Usuário acessa a página
        |
Frontend carrega site key pública
        |
Frontend executa reCAPTCHA com action esperada
        |
Frontend envia token ao backend
        |
Backend cria assessment no reCAPTCHA Enterprise
        |
Backend valida token, action, hostname e challenge
        |
Backend decide ALLOW, DENY ou ERROR
        |
Aplicação executa autenticação real
        |
Aplicação pode anotar o assessment após conhecer o resultado final
```

## Escopo deste projeto

Este projeto é uma referência técnica de integração.

Não cobre:

- autenticação real de usuário;
- persistência de sessão;
- MFA;
- rate limit;
- bloqueio por conta;
- trilha completa de auditoria;
- regras antifraude avançadas;
- integração com SIEM.