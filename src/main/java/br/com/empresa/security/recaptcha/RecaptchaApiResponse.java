package br.com.empresa.security.recaptcha;

public record RecaptchaApiResponse(
        String decision,
        String message,
        String assessmentId
) {
}
