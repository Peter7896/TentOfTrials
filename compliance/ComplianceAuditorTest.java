package com.tentoftrials.compliance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public final class ComplianceAuditorTest {
    public static void main(String[] args) throws Exception {
        passwordCredentialsLoadWhenFallbackAllowed();
        privateKeyCredentialsTakePrecedence();
        environmentBackedCredentialsLoad();
        missingCredentialsFailWithStructuredError();
        passwordFallbackDisabledDoesNotLeakSecret();
    }

    private static void passwordCredentialsLoadWhenFallbackAllowed() {
        ComplianceAuditor.SftpCredentialSource source = ComplianceAuditor.SftpCredentialSource.explicit(
            "regulator-user",
            "super-secret-password",
            null,
            true
        );

        ComplianceAuditor.SftpCredentials credentials = source.load();

        assertEquals(ComplianceAuditor.SftpAuthMethod.PASSWORD, credentials.getAuthMethod(), "auth method");
        assertEquals("regulator-user", credentials.getUsername(), "username");
        assertTrue(credentials.hasPasswordSecret(), "password secret should be present");
        assertFalse(credentials.redactedSummary().contains("super-secret-password"), "redacted summary leaked password");

        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", source);
        assertTrue(auditor.transmitToRegulator(new byte[] {1, 2, 3}, "report.pdf"), "password-backed transmit");
    }

    private static void privateKeyCredentialsTakePrecedence() throws Exception {
        Path keyPath = Files.createTempFile("regulator-sftp", ".key");
        Files.writeString(keyPath, "fake-test-key");
        try {
            ComplianceAuditor.SftpCredentialSource source = ComplianceAuditor.SftpCredentialSource.explicit(
                "regulator-user",
                "fallback-password",
                keyPath.toString(),
                true
            );

            ComplianceAuditor.SftpCredentials credentials = source.load();

            assertEquals(ComplianceAuditor.SftpAuthMethod.PRIVATE_KEY, credentials.getAuthMethod(), "auth method");
            assertEquals(keyPath, credentials.getPrivateKeyPath(), "private key path");
            assertFalse(credentials.hasPasswordSecret(), "private key auth should not retain fallback password");
            assertFalse(credentials.redactedSummary().contains("fallback-password"), "redacted summary leaked fallback password");
        } finally {
            Files.deleteIfExists(keyPath);
        }
    }

    private static void environmentBackedCredentialsLoad() {
        Map<String, String> environment = new HashMap<>();
        environment.put("REGULATOR_SFTP_USERNAME", "env-user");
        environment.put("REGULATOR_SFTP_PASSWORD", "env-password");
        environment.put("REGULATOR_SFTP_ALLOW_PASSWORD_FALLBACK", "true");

        ComplianceAuditor.SftpCredentials credentials =
            ComplianceAuditor.SftpCredentialSource.fromEnvironment(environment).load();

        assertEquals(ComplianceAuditor.SftpAuthMethod.PASSWORD, credentials.getAuthMethod(), "env auth method");
        assertEquals("env-user", credentials.getUsername(), "env username");
        assertFalse(credentials.redactedSummary().contains("env-password"), "redacted summary leaked env password");
    }

    private static void missingCredentialsFailWithStructuredError() {
        ComplianceAuditor.SftpCredentialSource source = ComplianceAuditor.SftpCredentialSource.explicit(
            "regulator-user",
            null,
            null,
            true
        );

        ComplianceAuditor.CredentialLoadException error = expectCredentialError(source::load);

        assertEquals("REGULATOR_SFTP_CREDENTIALS_MISSING", error.getCode(), "missing credential code");
        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", source);
        assertFalse(auditor.transmitToRegulator(new byte[] {1}, "missing.pdf"), "missing credentials should block transmit");
    }

    private static void passwordFallbackDisabledDoesNotLeakSecret() {
        String secret = "disabled-fallback-secret";
        ComplianceAuditor.SftpCredentialSource source = ComplianceAuditor.SftpCredentialSource.explicit(
            "regulator-user",
            secret,
            null,
            false
        );

        ComplianceAuditor.CredentialLoadException error = expectCredentialError(source::load);

        assertEquals("REGULATOR_SFTP_PASSWORD_FALLBACK_DISABLED", error.getCode(), "fallback disabled code");
        assertFalse(error.getMessage().contains(secret), "exception message leaked password");
        assertFalse(error.getSafeMessage().contains(secret), "safe message leaked password");
    }

    private static ComplianceAuditor.CredentialLoadException expectCredentialError(Runnable action) {
        try {
            action.run();
        } catch (ComplianceAuditor.CredentialLoadException error) {
            return error;
        }
        throw new AssertionError("Expected CredentialLoadException");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(message + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }
}
