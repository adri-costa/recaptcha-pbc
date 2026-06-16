package br.com.empresa.security.recaptcha;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RecaptchaController {

    private static final String LOGIN_ACTION = "login";

    private final RecaptchaService recaptchaService;
    private final RequestMetadataResolver requestMetadataResolver;
    private final RecaptchaProperties properties;

    public RecaptchaController(
            RecaptchaService recaptchaService,
            RequestMetadataResolver requestMetadataResolver,
            RecaptchaProperties properties
    ) {
        this.recaptchaService = recaptchaService;
        this.requestMetadataResolver = requestMetadataResolver;
        this.properties = properties;
    }

    @GetMapping("/recaptcha/config")
    public RecaptchaAppConfigResponse config() {
        return new RecaptchaAppConfigResponse(
                properties.siteKey(),
                LOGIN_ACTION
        );
    }

    @PostMapping("/auth/login")
    public ResponseEntity<RecaptchaApiResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        ClientRequestMetadata metadata = requestMetadataResolver.resolve(httpRequest);

        RecaptchaValidationResult result = recaptchaService.validate(
                request.recaptchaToken(),
                LOGIN_ACTION,
                metadata.userAgent(),
                metadata.clientIpAddress()
        );

        if (result.decision() == RecaptchaDecision.DENY) {
            return ResponseEntity.status(403).body(new RecaptchaApiResponse(
                    "DENY",
                    "Request blocked by reCAPTCHA validation.",
                    result.assessmentId()
            ));
        }

        if (result.decision() == RecaptchaDecision.ERROR) {
            return ResponseEntity.status(503).body(new RecaptchaApiResponse(
                    "ERROR",
                    "reCAPTCHA verification is temporarily unavailable.",
                    result.assessmentId()
            ));
        }

        /*
         * Real authentication must happen here:
         * - credential validation
         * - MFA or other step-up controls
         * - session issuance
         * - audit trail
         *
         * Never authenticate a user only because reCAPTCHA passed.
         * After your application reaches a final outcome, annotate the
         * assessment as LEGITIMATE or FRAUDULENT to improve your model.
         */

        return ResponseEntity.ok(new RecaptchaApiResponse(
                "ALLOW",
                "Login request passed reCAPTCHA validation.",
                result.assessmentId()
        ));
    }
}
