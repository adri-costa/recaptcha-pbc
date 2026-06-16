package br.com.empresa.security.recaptcha;

public record RecaptchaValidationResult(
        RecaptchaDecision decision,
        String assessmentId,
        Double score,
        String challenge,
        String returnedAction,
        String invalidReason
) {
}
