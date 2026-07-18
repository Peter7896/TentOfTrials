package com.tentoftrials.compliance;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public final class ComplianceAuditFailureTest {
    public static void main(String[] args) {
        failingAuditPathReturnsNonCompliantResult();
        defaultAuditPathStillRecordsSuccessfulChecks();
    }

    private static void failingAuditPathReturnsNonCompliantResult() {
        String secret = "secret-customer-token";
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            ComplianceAuditor.SftpCredentialSource.explicit("regulator-user", "password", null, true)::load,
            ComplianceAuditor.ComplianceOverrideLoader.disabled(),
            (checkType, data) -> {
                throw new IllegalStateException("validator crashed with token=" + secret);
            }
        );

        Map<String, Object> data = new HashMap<>();
        data.put("customer_id", "customer-123");
        data.put("api_token", secret);

        ComplianceAuditor.ComplianceResult result = auditor.auditCompliance("KYC", data);

        assertFalse(result.isCompliant(), "failing audit must fail closed");
        assertEquals(1, auditor.getAuditRecordCount(), "failed audit should still keep traceability record");
        ComplianceAuditor.ComplianceRecord record = onlyRecord(auditor.getAuditRecordsSnapshot());
        assertEquals("KYC", record.getCheckType(), "traceability record check type");
        assertEquals("customer-123", record.getData().get("customer_id"), "traceability record customer id");
        assertTrue(result.getSummary().contains("KYC"), "summary should include check type");
        assertTrue(result.getSummary().contains("IllegalStateException"), "summary should include sanitized error class");
        assertTrue(result.getSummary().contains("token=[REDACTED]"), "summary should include redaction marker");
        assertFalse(result.getSummary().contains(secret), "summary leaked secret token value");
        assertFalse(result.getViolations().isEmpty(), "failed audit should include a violation");
    }

    private static void defaultAuditPathStillRecordsSuccessfulChecks() {
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            "regulator-user",
            "password"
        );

        Map<String, Object> data = new HashMap<>();
        data.put("user_id", "user-123");
        data.put("kyc_status", "approved");
        data.put("is_pep", false);

        ComplianceAuditor.ComplianceResult result = auditor.auditCompliance("KYC", data);

        assertTrue(result.isCompliant(), "normal KYC audit should still pass");
        assertEquals(1, auditor.getAuditRecordCount(), "successful audit should keep traceability record");
    }

    private static ComplianceAuditor.ComplianceRecord onlyRecord(
        Collection<ComplianceAuditor.ComplianceRecord> records
    ) {
        assertEquals(1, records.size(), "record count");
        return records.iterator().next();
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
