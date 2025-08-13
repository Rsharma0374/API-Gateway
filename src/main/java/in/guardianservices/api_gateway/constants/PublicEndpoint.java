package in.guardianservices.api_gateway.constants;

import lombok.Getter;

public enum PublicEndpoint {

    //api gateway url
    APIGW_KEY("/gateway/key", false, false),

    //auth service url
    USER_HELLO("/auth-service/user/hello", false, false),
    AUTH_VALIDATE_TOKEN("/auth-service/auth/validate-token", false, true),
    COMM_VALIDATE_OTP_RESET_PASSWORD("/auth-service/communications/validate-otp-reset-password", true, false),
    COMM_VALIDATE_EMAIL_OTP("/auth-service/communications/validate-email-otp", true, false),
    AUTH_VALIDATE_TFA_OTP("/auth-service/auth/validate-tfa-otp", true, false),
    USER_SEND_EMAIL_OTP("/auth-service/user/send-email-otp", true, false),
    COMM_SEND_EMAIL_OTP("/auth-service/communications/send-email-otp", true, false),
    AUTH_FORGET_PASSWORD("/auth-service/auth/forget-password", true, false),
    AUTH_USER_LOGIN("/auth-service/auth/user-login", true, false),
    AUTH_CREATE_USER("/auth-service/auth/create-user", true, false),
    AUTH_LOGOUT("/auth-service/auth/logout", true, true),

    //email connector service
    EMAIL_WELCOME("/email-connector/welcome", false, false),
    EMAIL_SEND_MAIL("/email-connector/send-mail", true, true),
    EMAIL_SEND_PORTFOLIO_MESSAGE("/email-connector/send-portfolio-message", false, false),
    EMAIL_GET_CURRENT_DAY_STATS("/email-connector/get-current-day-statistics", false, false),

    //doc utility service
    DOCUMENT_UTILITY_WELCOME("/doc-service/welcome", false, false),
    DOCUMENT_UTILITY_LOCK("/doc-service/pdf/lock", false, false),
    DOCUMENT_UTILITY_UNLOCK("/doc-service/pdf/unlock", false, false),
    DOCUMENT_UTILITY_PDF_TO_BASE64("/doc-service/pdf-to-base64", false, false),
    DOCUMENT_UTILITY_BASE64_TO_PDF("/doc-service/base64-to-pdf", false, false),
    DOCUMENT_UTILITY_PDF_COMPRESS("/doc-service/pdf/compress", false, false),
    DOCUMENT_UTILITY_PDF_MERGE("/doc-service/pdf/merge", false, false),
    DOCUMENT_UTILITY_PDF_SPLIT("/doc-service/pdf/split", false, false),
    DOCUMENT_UTILITY_PDF_TO_IMAGES("/doc-service/pdf/to-images", false, false),
    DOCUMENT_UTILITY_PDF_TO_IMAGES_ASYNC("/doc-service/pdf/to-images/async", false, false),

    // payment service
    PAYMENT_CREATE_ORDER("/payment-service/api/v1/create-order", true, false),
    PAYMENT_GET_KEY("/payment-service/api/v1/get-key", true, false);

    @Getter
    private final String path;
    private final boolean requiresDecryption;
    private final boolean tokenRequired;

    PublicEndpoint(String path, boolean requiresDecryption, boolean tokenRequired) {
        this.path = path;
        this.requiresDecryption = requiresDecryption;
        this.tokenRequired = tokenRequired;
    }

    public boolean requiresDecryption() {
        return requiresDecryption;
    }

    public boolean tokenRequired() {
        return tokenRequired;
    }

    public static boolean isPublicEndpoint(String url) {
        for (PublicEndpoint endpoint : values()) {
            if (endpoint.getPath().equals(url)) {
                return true;
            }
        }
        return false;
    }

    public static boolean requiresDecryption(String url) {
        for (PublicEndpoint endpoint : values()) {
            if (endpoint.getPath().equals(url)) {
                return endpoint.requiresDecryption();
            }
        }
        return true;
    }

    public static boolean tokenRequired(String url) {
        for (PublicEndpoint endpoint : values()) {
            if (endpoint.getPath().equals(url)) {
                return endpoint.tokenRequired();
            }
        }
        return true;
    }
}
