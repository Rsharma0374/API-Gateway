package in.guardianservices.api_gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.infisical.sdk.InfisicalSdk;
import com.infisical.sdk.config.SdkConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Properties;

import static in.guardianservices.api_gateway.util.ResponseUtility.fetchProperties;

public class InfisicalConfig {

    private static final String INFISICAL_PATH = "/opt/configs/infisical.properties";

    private static final Logger logger = LoggerFactory.getLogger(InfisicalConfig.class);

    public static Map fetchConfig(String secretName) throws Exception {
        Properties properties = fetchProperties(INFISICAL_PATH);

        try {
            if (null != properties) {
                String infisicalUrl = properties.getProperty("url");
                String infisicalToken = properties.getProperty("token");
                String env = properties.getProperty("env");

                var sdk = new InfisicalSdk(
                        new SdkConfig.Builder()
                                .withSiteUrl(infisicalUrl)
                                .build()
                );

                sdk.Auth().SetAccessToken(infisicalToken);

                var secret = sdk.Secrets().GetSecret(
                        secretName,
                        "guardian-services",
                        env,
                        "/",
                        null, // Expand Secret References (boolean, optional)
                        null, // Include Imports (boolean, optional)
                        null  // Secret Type (shared/personal, defaults to shared, optional)
                );
                if (secret != null) {
                    ObjectMapper objectMapper = new ObjectMapper();
                    return objectMapper.readValue(secret.getSecretValue(), Map.class);
                }

            }
        } catch (Exception e) {
            logger.error("Exception occurred due to ", e);
            return null;
        }

        return null;
    }
}
