package br.com.empresa.security.recaptcha;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@ConfigurationPropertiesScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

// Controlador REST para lidar com as requisições de 'login' e do reCAPTCHA.
@RestController
class RecaptchaController {

    private static final Logger log = LoggerFactory.getLogger(RecaptchaController.class);
    private static final String GOOGLE_RECAPTCHA_URL = "https://recaptchaenterprise.googleapis.com";
    private static final String LOGIN_ACTION = "login";

    private final RecaptchaProperties properties;
    private final WebClient webClient;

    RecaptchaController(RecaptchaProperties properties, WebClient.Builder builder) {
        this.properties = properties;
        this.webClient = builder.baseUrl(GOOGLE_RECAPTCHA_URL).build();
    }

    /*
     * FRONTEND chama este endpoint para buscar a SITE KEY pública.
     */
    @GetMapping("/api/recaptcha/config")
    public Map<String, String> recaptchaConfig() {
        return Map.of(
                "siteKey", properties.siteKey(),
                "action", LOGIN_ACTION
        );
    }

    /*
     * FRONTEND envia username, password e recaptchaToken para o BACKEND.
     * BACKEND chama o Google e cria o assessment.
     */
    @PostMapping("/api/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        RecaptchaAssessment assessment = createAssessment(
                request.recaptchaToken(),
                LOGIN_ACTION,
                httpRequest.getHeader("User-Agent"),
                httpRequest.getRemoteAddr()
        );

        if (assessment == null) {
            return ResponseEntity.status(503).body(Map.of(
                    "decision", "ERROR",
                    "message", "Erro ao validar reCAPTCHA"
            ));
        }

        boolean tokenValid = assessment.tokenProperties() != null
                && Boolean.TRUE.equals(assessment.tokenProperties().valid());

        String returnedAction = assessment.tokenProperties() != null
                ? assessment.tokenProperties().action()
                : null;

        String hostname = assessment.tokenProperties() != null
                ? assessment.tokenProperties().hostname()
                : null;

        Double score = assessment.riskAnalysis() != null
                ? assessment.riskAnalysis().score()
                : null;

        String challenge = assessment.riskAnalysis() != null
                ? assessment.riskAnalysis().challenge()
                : null;

        List<String> reasons = assessment.riskAnalysis() != null
                ? assessment.riskAnalysis().reasons()
                : List.of();

        log.info(
                "recaptcha assessmentId={} tokenValid={} actionExpected={} actionReturned={} hostname={} score={} challenge={} reasons={}",
                assessment.name(),
                tokenValid,
                LOGIN_ACTION,
                returnedAction,
                hostname,
                score,
                challenge,
                reasons
        );

        /*
         * Validações do token e outras propriedades.
         */
        if (!tokenValid) {
            return deny("Token inválido", assessment.name(), score, challenge, reasons);
        }

        if (!LOGIN_ACTION.equalsIgnoreCase(returnedAction)) {
            return deny("Action divergente", assessment.name(), score, challenge, reasons);
        }

        if (!properties.expectedHostname().isBlank()
                && !properties.expectedHostname().equalsIgnoreCase(hostname)) {
            return deny("Hostname divergente", assessment.name(), score, challenge, reasons);
        }

        if ("FAIL".equalsIgnoreCase(challenge)) {
            return deny("Challenge falhou", assessment.name(), score, challenge, reasons);
        }

        /*
         * Aqui entra a autenticação da aplicação.
         * Nste exemplo só mostra o reCAPTCHA, não loga na aplicação.
         */
        return ResponseEntity.ok(Map.of(
                "decision", "ALLOW",
                "message", "reCAPTCHA validado com sucesso",
                "assessmentId", assessment.name(),
                "score", score,
                "challenge", challenge,
                "reasons", reasons
        ));
    }

    /*
     * BACKEND chama o Google reCAPTCHA Enterprise.
     */
    private RecaptchaAssessment createAssessment(
            String token,
            String expectedAction,
            String userAgent,
            String userIpAddress
    ) {
        Map<String, Object> body = Map.of(
                "event", Map.of(
                        "token", token,
                        "siteKey", properties.siteKey(),
                        "expectedAction", expectedAction,
                        "userAgent", userAgent == null ? "" : userAgent,
                        "userIpAddress", userIpAddress == null ? "" : userIpAddress
                )
        );

        try {
            return webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .path("/v1/projects/{projectId}/assessments")
                            .queryParam("key", properties.apiKey())
                            .build(properties.projectId()))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(RecaptchaAssessment.class)
                    .timeout(Duration.ofMillis(properties.timeoutMs()))
                    .block();

        } catch (WebClientResponseException ex) {
            log.warn(
                    "recaptcha_http_error status={} response={}",
                    ex.getStatusCode().value(),
                    compact(ex.getResponseBodyAsString())
            );
            return null;

        } catch (RuntimeException ex) {
            log.warn("recaptcha_error={}", ex.getMessage());
            return null;
        }
    }

    private ResponseEntity<Map<String, Object>> deny(
            String message,
            String assessmentId,
            Double score,
            String challenge,
            List<String> reasons
    ) {
        return ResponseEntity.status(403).body(Map.of(
                "decision", "DENY",
                "message", message,
                "assessmentId", assessmentId,
                "score", score,
                "challenge", challenge,
                "reasons", reasons
        ));
    }

    private String compact(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }
}

@Validated
@ConfigurationProperties(prefix = "recaptcha")
record RecaptchaProperties(
        @NotBlank String projectId,
        @NotBlank String siteKey,
        @NotBlank String apiKey,
        @NotBlank String expectedHostname,
        Integer timeoutMs
) {
}

record LoginRequest(
        @NotBlank String username,
        @NotBlank String password,
        @NotBlank String recaptchaToken
) {
}

record RecaptchaAssessment(
        String name,
        TokenProperties tokenProperties,
        RiskAnalysis riskAnalysis
) {
}

record TokenProperties(
        Boolean valid,
        String invalidReason,
        String hostname,
        String action
) {
}

record RiskAnalysis(
        Double score,
        List<String> reasons,
        List<String> extendedVerdictReasons,
        String challenge
) {
}