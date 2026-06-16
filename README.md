# reCAPTCHA - Policy-Based Challenge

Aplicação Java Spring Boot para ser utilizada como referencia na utilização de chave reCAPTCHA do tipo policy-based challenge.

## Demonstrado nesse projeto

- Integração da chave publica com o navegador
- Gerando o token no frontend
- Criação do assessment no backend
- Validação de action, token validity, hostname e challenge
- Opção de uso do annotation no assessment

## Prerequisitos

- Java 17
- Maven 3.9+
- Projeto na GCP com reCAPTCHA Enterprise habilitado
- Uma site-key criada com policy-based challenge

## Variáveis do environment

```powershell
$env:RECAPTCHA_PROJECT_ID="your-gcp-project-id"
$env:RECAPTCHA_SITE_KEY="your-public-site-key"
$env:RECAPTCHA_API_KEY="your-backend-api-key"
$env:RECAPTCHA_EXPECTED_HOSTNAME="your-hostname"
```

Notes:

- `RECAPTCHA_SITE_KEY` é público e pode ficar exposto no navegador.
- `RECAPTCHA_API_KEY` deve estar e ser restrito ao backend.
- `RECAPTCHA_EXPECTED_HOSTNAME` é opicional mas recomendado quando se sabe o nome do host (ex. localhost).

## Execução local

```powershell
mvn spring-boot:run
```

Então acessar:

```text
http://localhost:8080
```

## Execução de testes

```powershell
mvn test
```

## Notas de Segurança

- Não permitir a ação apenas porque o reCAPTCHA returnou `ALLOW`.
- Criar o assessment dentro de 2 minutos (expiração do token).
- Apenas confie em `X-Forwarded-For` ou `X-Real-IP` quando a aplicação estiver atrás de um proxy.
- Apensa utilize o annotation quando os assessments estiverem com reasons ou score fora do esperado pela aplicação.
- As variávies estão expostas por se tratar de uma demonstração. 
