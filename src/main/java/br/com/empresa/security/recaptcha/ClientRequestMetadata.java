package br.com.empresa.security.recaptcha;

public record ClientRequestMetadata(
        String userAgent,
        String clientIpAddress
) {
}
