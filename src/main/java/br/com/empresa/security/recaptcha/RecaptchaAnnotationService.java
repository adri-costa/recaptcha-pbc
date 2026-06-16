package br.com.empresa.security.recaptcha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RecaptchaAnnotationService {

    private static final Logger log = LoggerFactory.getLogger(RecaptchaAnnotationService.class);

    private final RecaptchaClient recaptchaClient;
    private final RecaptchaProperties properties;

    public RecaptchaAnnotationService(
            RecaptchaClient recaptchaClient,
            RecaptchaProperties properties
    ) {
        this.recaptchaClient = recaptchaClient;
        this.properties = properties;
    }

    public void annotateLegitimate(String assessmentId, List<String> reasons) {
        annotate(assessmentId, "LEGITIMATE", reasons);
    }

    public void annotateFraudulent(String assessmentId, List<String> reasons) {
        annotate(assessmentId, "FRAUDULENT", reasons);
    }

    private void annotate(String assessmentId, String annotation, List<String> reasons) {
        if (!properties.annotationsEnabled()) {
            return;
        }

        if (assessmentId == null || assessmentId.isBlank()) {
            return;
        }

        try {
            recaptchaClient.annotateAssessment(assessmentId, annotation, reasons);
            log.info(
                    "recaptcha_annotation_sent assessment_id={} annotation={} reasons={}",
                    assessmentId,
                    annotation,
                    reasons
            );
        } catch (RuntimeException ex) {
            log.warn(
                    "recaptcha_annotation_failed assessment_id={} annotation={} error={}",
                    assessmentId,
                    annotation,
                    ex.getMessage()
            );
        }
    }
}
