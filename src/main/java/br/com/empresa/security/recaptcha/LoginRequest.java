package br.com.empresa.security.recaptcha;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank String username,
        @NotBlank String password,
        @NotBlank String recaptchaToken
) {
}
