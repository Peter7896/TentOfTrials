package com.tentoftrials.compliance;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

public final class ComplianceReportTest {
    public static void main(String[] args) {
        validRangeReturnsNonEmptyReportWithAuditRows();
        failClosedAuditResultAppearsInReport();
        emptyRangeStillReturnsStructuredReport();
        invalidRangeFailsClearly();
    }

    private static void validRangeReturnsNonEmptyReportWithAuditRows() {
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            "regulator-user",
            "password"
        );

        Map<String, Object> data = new HashMap<>();
        data.put("user_id", "user-123");
        data.put("kyc_status", "pending");
        data.put("is_pep", true);

        auditor.auditCompliance("KYC", data);

        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        byte[] bytes = auditor.generateReport(todayUtc.minusDays(1), todayUtc.plusDays(1));
        String report = new String(bytes, StandardCharsets.UTF_8);

        assertTrue(bytes.length > 0, "report should not be empty");
        assertTrue(report.contains("report_format,compliance-audit-csv-v1"), "report format metadata");
        assertTrue(report.contains("period_start," + todayUtc.minusDays(1)), "period start metadata");
        assertTrue(report.contains("period_end," + todayUtc.plusDays(1)), "period end metadata");
        assertTrue(report.contains("record_count,1"), "record count metadata");
        assertTrue(
            report.contains("check_id,check_type,timestamp,compliant,violations_summary"),
            "report header"
        );
        assertTrue(report.contains(",KYC,"), "check type");
        assertTrue(report.contains(",false,"), "compliance status");
        assertTrue(report.contains("User user-123 has not completed KYC"), "violations summary");
        assertTrue(report.contains("Enhanced due diligence required"), "second violation summary");
    }

    private static void failClosedAuditResultAppearsInReport() {
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            () -> ComplianceAuditor.SftpCredentials.forPassword("regulator-user", "password"),
            ComplianceAuditor.ComplianceOverrideLoader.disabled(),
            (checkType, data) -> {
                throw new IllegalStateException("token=raw-secret");
            }
        );

        auditor.auditCompliance("CUSTOM_RULE", new HashMap<>());

        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        String report = new String(
            auditor.generateReport(todayUtc.minusDays(1), todayUtc.plusDays(1)),
            StandardCharsets.UTF_8
        );

        assertTrue(report.contains(",CUSTOM_RULE,"), "failed check type");
        assertTrue(report.contains(",false,"), "failed check compliance status");
        assertTrue(report.contains("Audit execution failed for CUSTOM_RULE"), "failed audit summary");
        assertTrue(report.contains("token=[REDACTED]"), "failed audit redacts sensitive tokens");
        assertTrue(!report.contains("raw-secret"), "failed audit must not leak raw secret");
    }

    private static void emptyRangeStillReturnsStructuredReport() {
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            "regulator-user",
            "password"
        );

        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        String report = new String(
            auditor.generateReport(todayUtc.minusDays(10), todayUtc.minusDays(9)),
            StandardCharsets.UTF_8
        );

        assertTrue(report.contains("record_count,0"), "empty range record count");
        assertTrue(
            report.contains("check_id,check_type,timestamp,compliant,violations_summary"),
            "empty range header"
        );
    }

    private static void invalidRangeFailsClearly() {
        ComplianceAuditor auditor = new ComplianceAuditor(
            "sftp://regulator.example",
            "regulator-user",
            "password"
        );

        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        IllegalArgumentException error = expectInvalidRange(
            () -> auditor.generateReport(todayUtc, todayUtc.minusDays(1))
        );

        assertTrue(error.getMessage().contains("end date"), "invalid range message");
    }

    private static IllegalArgumentException expectInvalidRange(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException error) {
            return error;
        }
        throw new AssertionError("Expected IllegalArgumentException");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
