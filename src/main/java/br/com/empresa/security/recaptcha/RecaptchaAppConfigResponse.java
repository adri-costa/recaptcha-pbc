package br.com.empresa.security.recaptcha;

public record RecaptchaAppConfigResponse(
        String siteKey,
        String loginAction
) {
}
