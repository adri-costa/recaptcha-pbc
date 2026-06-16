package br.com.empresa.security.recaptcha;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class RequestMetadataResolver {

    private final RecaptchaProperties properties;

    public RequestMetadataResolver(RecaptchaProperties properties) {
        this.properties = properties;
    }

    public ClientRequestMetadata resolve(HttpServletRequest request) {
        return new ClientRequestMetadata(
                safe(request.getHeader("User-Agent")),
                resolveClientIp(request)
        );
    }

    private String resolveClientIp(HttpServletRequest request) {
        if (properties.trustProxyHeaders()) {
            String forwardedFor = firstNonBlank(
                    request.getHeader("X-Forwarded-For"),
                    request.getHeader("X-Real-IP")
            );
            if (!forwardedFor.isBlank()) {
                return forwardedFor.split(",")[0].trim();
            }
        }

        return safe(request.getRemoteAddr());
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
