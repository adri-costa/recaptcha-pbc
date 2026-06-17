package br.com.empresa.security.recaptcha;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank
        @Size(max = 150)
        String username,

        @NotBlank
        @Size(max = 200)
        String password,

        @NotBlank
        @Size(max = 4096)
        String recaptchaToken
) {
}