package br.com.empresa.security.recaptcha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class RecaptchaService {

    private static final Logger log = LoggerFactory.getLogger(RecaptchaService.class);

    private final RecaptchaClient recaptchaClient;
    private final RecaptchaProperties properties;

    public RecaptchaService(
            RecaptchaClient recaptchaClient,
            RecaptchaProperties properties
    ) {
        this.recaptchaClient = recaptchaClient;
        this.properties = properties;
    }

    public RecaptchaValidationResult validate(
            String token,
            String expectedAction,
            String userAgent,
            String userIpAddress
    ) {
        if (token == null || token.isBlank()) {
            return deny(
                    null,
                    null,
                    null,
                    null,
                    null,
                    "MISSING_TOKEN"
            );
        }

        RecaptchaAssessmentResponse assessment;

        try {
            assessment = recaptchaClient.createAssessment(
                    token,
                    expectedAction,
                    userAgent,
                    userIpAddress
            );

        } catch (RuntimeException ex) {
            log.warn("recaptcha_assessment_error action={} error={}", expectedAction, ex.getMessage());
            return error(null);
        }

        if (assessment == null) {
            log.warn("recaptcha_assessment_null action={}", expectedAction);
            return error(null);
        }

        var tokenProperties = assessment.tokenProperties();
        var riskAnalysis = assessment.riskAnalysis();

        String assessmentId = assessment.name();
        Boolean tokenValid = tokenProperties != null ? tokenProperties.valid() : Boolean.FALSE;
        String returnedAction = tokenProperties != null ? tokenProperties.action() : null;
        String invalidReason = tokenProperties != null ? tokenProperties.invalidReason() : null;
        String hostname = tokenProperties != null ? tokenProperties.hostname() : null;
        Double score = riskAnalysis != null ? riskAnalysis.score() : null;
        String challenge = riskAnalysis != null ? riskAnalysis.challenge() : null;

        log.info(
                "recaptcha_assessment assessment_id={} action_expected={} action_returned={} token_valid={} invalid_reason={} hostname={} score={} challenge={} reasons={}",
                assessmentId,
                expectedAction,
                returnedAction,
                tokenValid,
                invalidReason,
                hostname,
                score,
                challenge,
                riskAnalysis != null ? riskAnalysis.reasons() : null
        );

        if (challenge == null || challenge.isBlank()) {
            log.info(
                    "recaptcha_challenge_empty assessment_id={} action_expected={} score={}",
                    assessmentId,
                    expectedAction,
                    score
            );
        }

        if (!Boolean.TRUE.equals(tokenValid)) {
            return deny(
                    assessmentId,
                    score,
                    challenge,
                    returnedAction,
                    invalidReason,
                    "TOKEN_INVALID"
            );
        }

        if (returnedAction == null || !returnedAction.equalsIgnoreCase(expectedAction)) {
            return deny(
                    assessmentId,
                    score,
                    challenge,
                    returnedAction,
                    invalidReason,
                    "ACTION_MISMATCH"
            );
        }

        if (isHostnameMismatch(hostname)) {
            return deny(
                    assessmentId,
                    score,
                    challenge,
                    returnedAction,
                    invalidReason,
                    "HOSTNAME_MISMATCH"
            );
        }

        if ("FAIL".equalsIgnoreCase(challenge)) {
            return deny(
                    assessmentId,
                    score,
                    challenge,
                    returnedAction,
                    invalidReason,
                    "CHALLENGE_FAILED"
            );
        }

        return allow(
                assessmentId,
                score,
                challenge,
                returnedAction,
                invalidReason
        );
    }

    private boolean isHostnameMismatch(String hostname) {
        return properties.expectedHostname() != null
                && !properties.expectedHostname().isBlank()
                && (hostname == null || !hostname.equalsIgnoreCase(properties.expectedHostname()));
    }

    private RecaptchaValidationResult allow(
            String assessmentId,
            Double score,
            String challenge,
            String returnedAction,
            String invalidReason
    ) {
        return new RecaptchaValidationResult(
                RecaptchaDecision.ALLOW,
                assessmentId,
                score,
                challenge,
                returnedAction,
                invalidReason,
                "VALID_RECAPTCHA_ASSESSMENT"
        );
    }

    private RecaptchaValidationResult deny(
            String assessmentId,
            Double score,
            String challenge,
            String returnedAction,
            String invalidReason,
            String decisionReason
    ) {
        return new RecaptchaValidationResult(
                RecaptchaDecision.DENY,
                assessmentId,
                score,
                challenge,
                returnedAction,
                invalidReason,
                decisionReason
        );
    }

    private RecaptchaValidationResult error(String assessmentId) {
        return new RecaptchaValidationResult(
                RecaptchaDecision.ERROR,
                assessmentId,
                null,
                null,
                null,
                null,
                "RECAPTCHA_UNAVAILABLE"
        );
    }
}