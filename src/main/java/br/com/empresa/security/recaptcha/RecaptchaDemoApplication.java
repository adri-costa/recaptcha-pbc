package br.com.empresa.security.recaptcha;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RecaptchaDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(RecaptchaDemoApplication.class, args);
    }
}
