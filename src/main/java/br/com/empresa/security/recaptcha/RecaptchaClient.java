package br.com.empresa.security.recaptcha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@Component
public class RecaptchaClient {

    private static final Logger log = LoggerFactory.getLogger(RecaptchaClient.class);
    private static final String BASE_URL = "https://recaptchaenterprise.googleapis.com";

    private final WebClient webClient;
    private final RecaptchaProperties properties;

    public RecaptchaClient(WebClient.Builder builder, RecaptchaProperties properties) {
        this.properties = properties;
        this.webClient = builder
                .baseUrl(BASE_URL)
                .build();
    }

    public RecaptchaAssessmentResponse createAssessment(
            String token,
            String expectedAction,
            String userAgent,
            String userIpAddress
    ) {
        Map<String, Object> requestBody = Map.of(
                "event", Map.of(
                        "token", token,
                        "siteKey", properties.siteKey(),
                        "expectedAction", expectedAction,
                        "userAgent", safe(userAgent),
                        "userIpAddress", safe(userIpAddress)
                )
        );

        try {
            return webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .path("/v1/projects/{projectId}/assessments")
                            .queryParam("key", properties.apiKey())
                            .build(properties.projectId()))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(RecaptchaAssessmentResponse.class)
                    .timeout(Duration.ofMillis(properties.timeoutMs()))
                    .block();

        } catch (WebClientResponseException ex) {
            log.warn(
                    "recaptcha_create_assessment_http_error status={}",
                    ex.getStatusCode().value()
            );

            log.warn(
                    "recaptcha_create_assessment_http_error_response status={} response={}",
                    ex.getStatusCode().value(),
                    compact(ex.getResponseBodyAsString())
            );

            throw new RuntimeException("reCAPTCHA assessment request failed", ex);

        } catch (RuntimeException ex) {
            log.warn("recaptcha_create_assessment_error error={}", ex.getMessage());
            throw new RuntimeException("reCAPTCHA assessment request failed", ex);
        }
    }

    public void annotateAssessment(
            String assessmentId,
            String annotation,
            List<String> reasons
    ) {
        Map<String, Object> requestBody = Map.of(
                "annotation", annotation,
                "reasons", reasons == null ? List.of() : reasons
        );

        try {
            webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .path("/v1/{assessmentId}:annotate")
                            .queryParam("key", properties.apiKey())
                            .build(assessmentId))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(Void.class)
                    .switchIfEmpty(Mono.empty())
                    .timeout(Duration.ofMillis(properties.timeoutMs()))
                    .block();

        } catch (WebClientResponseException ex) {
            log.warn(
                    "recaptcha_annotate_http_error assessment_id={} status={}",
                    assessmentId,
                    ex.getStatusCode().value()
            );

            log.debug(
                    "recaptcha_annotate_http_error_response assessment_id={} status={} response={}",
                    assessmentId,
                    ex.getStatusCode().value(),
                    compact(ex.getResponseBodyAsString())
            );

            throw new RuntimeException("reCAPTCHA annotation request failed", ex);

        } catch (RuntimeException ex) {
            log.warn(
                    "recaptcha_annotate_error assessment_id={} error={}",
                    assessmentId,
                    ex.getMessage()
            );

            throw new RuntimeException("reCAPTCHA annotation request failed", ex);
        }
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String compact(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace('\n', ' ')
                .replace('\r', ' ')
                .trim();
    }
}