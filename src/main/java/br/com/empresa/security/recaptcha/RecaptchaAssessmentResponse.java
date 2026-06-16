package br.com.empresa.security.recaptcha;

import java.util.List;

public record RecaptchaAssessmentResponse(
        String name,
        TokenProperties tokenProperties,
        RiskAnalysis riskAnalysis,
        Event event
) {
    public record TokenProperties(
            Boolean valid,
            String invalidReason,
            String hostname,
            String action,
            String createTime
    ) {
    }

    public record RiskAnalysis(
            Double score,
            List<String> reasons,
            List<String> extendedVerdictReasons,
            String challenge
    ) {
    }

    public record Event(
            String expectedAction,
            String siteKey
    ) {
    }
}
