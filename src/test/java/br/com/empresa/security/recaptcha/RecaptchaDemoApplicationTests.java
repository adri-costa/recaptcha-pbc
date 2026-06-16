package br.com.empresa.security.recaptcha;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "recaptcha.project-id=test-project",
        "recaptcha.site-key=test-site-key",
        "recaptcha.api-key=test-api-key",
        "recaptcha.timeout-ms=3000",
        "recaptcha.expected-hostname=localhost",
        "recaptcha.trust-proxy-headers=false",
        "recaptcha.annotations-enabled=false"
})
class RecaptchaDemoApplicationTests {

    @Test
    void contextLoads() {
        // Smoke test: verifies the Spring context and configuration bindings load correctly.
    }
}
