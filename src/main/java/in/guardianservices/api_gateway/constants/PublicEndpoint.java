package in.guardianservices.api_gateway.constants;

import lombok.Getter;

public enum PublicEndpoint {

    USER_HELLO("/user/hello", false, false),
    APIGW_KEY("/gateway/key", false, false),
    AUTH_VALIDATE_TOKEN("/auth/validate-token", false, true),
    COMM_VALIDATE_OTP_RESET_PASSWORD("/communications/validate-otp-reset-password", true, false),
    COMM_VALIDATE_EMAIL_OTP("/communications/validate-email-otp", true, false),
    AUTH_VALIDATE_TFA_OTP("/auth/validate-tfa-otp", true, false),
    USER_SEND_EMAIL_OTP("/user/send-email-otp", true, false),
    COMM_SEND_EMAIL_OTP("/communications/send-email-otp", true, false),
    AUTH_FORGET_PASSWORD("/auth/forget-password", true, false),
    AUTH_USER_LOGIN("/auth/user-login", true, false),
    AUTH_CREATE_USER("/auth/create-user", true, false),
    AUTH_LOGOUT("/auth/logout", true, true),
    EMAIL_WELCOME("/email-connector/welcome", false, false),
    EMAIL_SEND_MAIL("/email-connector/send-mail", true, true),
    EMAIL_SEND_PORTFOLIO_MESSAGE("/email-connector/send-portfolio-message", false, false),
    EMAIL_GET_CURRENT_DAY_STATS("/email-connector/get-current-day-statistics", false, false),
    DOCUMENT_UTILITY_WELCOME("/doc-service/welcome", false, false),
    DOCUMENT_UTILITY_LOCK("/doc-service/pdf/lock", false, false),
    DOCUMENT_UTILITY_UNLOCK("/doc-service/pdf/unlock", false, false),
    DOCUMENT_UTILITY_PDF_TO_BASE64("/doc-service/pdf-to-base64", false, false),
    DOCUMENT_UTILITY_BASE64_TO_PDF("/doc-service/base64-to-pdf", false, false),
    DOCUMENT_UTILITY_PDF_COMPRESS("/doc-service/pdf/compress", false, false),
    DOCUMENT_UTILITY_PDF_MERGE("/doc-service/pdf/merge", false, false),
    DOCUMENT_UTILITY_PDF_SPLIT("/doc-service/pdf/split", false, false),
    DOCUMENT_UTILITY_PDF_TO_IMAGES("/doc-service/pdf/to-images", false, false);

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
