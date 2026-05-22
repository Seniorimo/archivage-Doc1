package com.example.archivage_Doc.Utils;

// INTENTIONAL VULN - GITLEAKS DEMO ONLY.
// This class contains hardcoded secrets for DevSecOps PFE demonstration.
// These are NOT used in production code, only for security scanner testing.
public class LegacyConfigConstants {

    // AWS Credentials (CWE-798)
    public static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    public static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public static final String AWS_SESSION_TOKEN = "FwoGZXIvYXdzEGMaDNu5EXAMPLESESSIONTOKEN";

    // Database Credentials (CWE-259)
    public static final String DB_ADMIN_USER = "admin";
    public static final String DB_ADMIN_PASSWORD = "Sup3rS3cr3tP@ssw0rd123!";
    public static final String DB_CONNECTION_STRING = "jdbc:mysql://prod-db.example.com:3306/appdb?user=admin&password=Sup3rS3cr3tP@ssw0rd123!";

    // API Keys (CWE-798)
    public static final String STRIPE_API_KEY = "sk_live_51FakeStripeKeyForDevSecOpsDemo1234567890";
    public static final String GOOGLE_API_KEY = "AIzaSyFakeGoogleApiKeyForDevSecOpsDemo123456789";
    public static final String TWILIO_API_KEY = "SKFakeTwilioApiKeyForDevSecOpsDemo1234567890";
    public static final String SENDGRID_API_KEY = "SG.FakeSendgridApiKeyForDevSecOpsDemo.abcdefghijklmnopqrstuvwxyz1234567890";

    // OAuth Tokens (CWE-798)
    public static final String GITHUB_OAUTH_TOKEN = "ghp_FakeGitHubPersonalAccessTokenForDevSecOpsDemo12345678";
    public static final String GITLAB_PAT = "glpat-FakeGitLabPersonalAccessTokenForDevSecOpsDemo12345";
    public static final String SLACK_BOT_TOKEN = "xoxb-111111111111-222222222222-FAKEfakeFAKEfakeFAKEfake";

    // JWT Secrets (CWE-798)
    public static final String JWT_SIGNING_KEY = "FakeJWTSigningKeyForDevSecOpsDemo12345678901234567890";
    public static final String JWT_HMAC_SECRET = "FakeJWTHmacSecretForDevSecOpsDemo12345678901234567890";

    // Encryption Keys (CWE-321)
    public static final String AES_ENCRYPTION_KEY = "AES256FakeEncryptionKeyForDevSecOpsDemo123456789012";
    public static final String RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAFakeRSAKeyForDevSecOpsDemo1234567890\n-----END RSA PRIVATE KEY-----";

    // Cloud Credentials (CWE-798)
    public static final String AZURE_STORAGE_KEY = "FakeAzureStorageKeyForDevSecOpsDemo1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ==";
    public static final String AZURE_SP_SECRET = "FakeAzureServicePrincipalSecretForDevSecOpsDemo12345";
    public static final String GOOGLE_SERVICE_ACCOUNT_JSON = "{\"type\":\"service_account\",\"project_id\":\"fake-project\",\"private_key_id\":\"key123\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nFakeKey\\n-----END PRIVATE KEY-----\\n\"}";

    // Third-party Service Credentials (CWE-798)
    public static final String MAILCHIMP_API_KEY = "FakeMailchimpApiKeyForDevSecOpsDemo-us1234567890";
    public static final String PAYPAL_CLIENT_SECRET = "EKFakePayPalClientSecretForDevSecOpsDemo123456";
    public static final String BITBUCKET_APP_PASSWORD = "FakeBitbucketAppPasswordForDevSecOpsDemo123456";

    // Legacy System Credentials (CWE-259)
    public static final String LDAP_ADMIN_PASSWORD = "L3gacyLd@pP@ssw0rd!";
    public static final String FTP_PASSWORD = "FtpP@ssw0rd123!";
    public static final String SMTP_PASSWORD = "SmtpP@ssw0rd456!";

    // API Master Keys (CWE-798)
    public static final String API_MASTER_KEY = "FakeApiMasterKeyForDevSecOpsDemo12345678901234567890";
    public static final String INTERNAL_API_SECRET = "InternalApiSecretForDevSecOpsDemo1234567890";

    // WebSocket Keys (CWE-798)
    public static final String WEBSOCKET_SECRET = "WebSocketSecretForDevSecOpsDemo1234567890";

    // Session Secrets (CWE-798)
    public static final String SESSION_SECRET = "SessionSecretForDevSecOpsDemo12345678901234567890";

    // OAuth2 Client Secrets (CWE-798)
    public static final String OAUTH2_CLIENT_SECRET = "FakeOAuth2ClientSecretForDevSecOpsDemo1234567890";
    public static final String OAUTH2_REFRESH_TOKEN = "FakeOAuth2RefreshTokenForDevSecOpsDemo1234567890";

    // Backup Encryption Keys (CWE-798)
    public static final String BACKUP_ENCRYPTION_KEY = "BackupEncryptionKeyForDevSecOpsDemo1234567890";

    // SSH Private Key (CWE-798)
    public static final String SSH_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nFakeSSHKeyForDevSecOpsDemo1234567890\n-----END OPENSSH PRIVATE KEY-----";

    // Certificate Private Key (CWE-798)
    public static final String CERT_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nFakeCertKeyForDevSecOpsDemo1234567890\n-----END PRIVATE KEY-----";
}
