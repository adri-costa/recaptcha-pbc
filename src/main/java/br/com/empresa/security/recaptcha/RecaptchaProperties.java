package br.com.empresa.security.recaptcha;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "recaptcha")
public record RecaptchaProperties(
        @NotBlank String projectId,
        @NotBlank String siteKey,
        @NotBlank String apiKey,
        @Positive Integer timeoutMs,
        String expectedHostname,
        boolean trustProxyHeaders,
        boolean annotationsEnabled
) {
}
