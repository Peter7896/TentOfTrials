package com.tentoftrials.compliance;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.time.Duration;

public final class ComplianceOverrideLoaderTest {
    public static void main(String[] args) throws Exception {
        classLoadingAndConstructionDoNotLoadOverrides();
        defaultOverrideLoadingIsDisabled();
        explicitInjectedOverrideLoadSucceeds();
        httpOverrideLoaderCanBeInjected();
        loaderFailuresReturnStructuredRedactedDiagnostics();
    }

    private static void classLoadingAndConstructionDoNotLoadOverrides() throws Exception {
        Class.forName("com.tentoftrials.compliance.ComplianceAuditor");

        CountingLoader loader = new CountingLoader(ComplianceAuditor.ComplianceOverrideLoadResult.loaded(13));
        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", "user", "password", loader);

        assertEquals(0, loader.loadCount, "constructor must not load overrides");
        assertEquals(
            ComplianceAuditor.ComplianceOverrideStatus.DISABLED,
            auditor.getOverrideLoadResult().getStatus(),
            "initial override status"
        );
    }

    private static void defaultOverrideLoadingIsDisabled() {
        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", "user", "password");

        ComplianceAuditor.ComplianceOverrideLoadResult result = auditor.loadComplianceOverrides();

        assertEquals(ComplianceAuditor.ComplianceOverrideStatus.DISABLED, result.getStatus(), "default status");
        assertEquals("COMPLIANCE_OVERRIDES_DISABLED", result.getCode(), "default diagnostic code");
    }

    private static void explicitInjectedOverrideLoadSucceeds() {
        CountingLoader loader = new CountingLoader(ComplianceAuditor.ComplianceOverrideLoadResult.loaded(27));
        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", "user", "password", loader);

        ComplianceAuditor.ComplianceOverrideLoadResult result = auditor.loadComplianceOverrides();

        assertEquals(1, loader.loadCount, "explicit load count");
        assertEquals(ComplianceAuditor.ComplianceOverrideStatus.LOADED, result.getStatus(), "injected load status");
        assertEquals(27, result.getBytesLoaded(), "bytes loaded");
    }

    private static void httpOverrideLoaderCanBeInjected() throws Exception {
        byte[] payload = "{\"offline\":false}".getBytes();
        URL url = new URL(null, "https://example.test/compliance-overrides.json", new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) {
                return new StubHttpURLConnection(u, payload);
            }
        });

        ComplianceAuditor.ComplianceOverrideLoader loader =
            ComplianceAuditor.s3OverrideLoader(url, Duration.ofMillis(50));

        ComplianceAuditor.ComplianceOverrideLoadResult result = loader.load();

        assertEquals(ComplianceAuditor.ComplianceOverrideStatus.LOADED, result.getStatus(), "http load status");
        assertEquals(payload.length, result.getBytesLoaded(), "http bytes loaded");
    }

    private static void loaderFailuresReturnStructuredRedactedDiagnostics() {
        ComplianceAuditor.ComplianceOverrideLoader loader = () -> {
            throw new IllegalStateException("request failed with token=secret-value");
        };
        ComplianceAuditor auditor = new ComplianceAuditor("sftp://regulator.example", "user", "password", loader);

        ComplianceAuditor.ComplianceOverrideLoadResult result = auditor.loadComplianceOverrides();

        assertEquals(ComplianceAuditor.ComplianceOverrideStatus.FAILED, result.getStatus(), "failure status");
        assertEquals("COMPLIANCE_OVERRIDE_LOADER_FAILED", result.getCode(), "failure code");
        assertFalse(result.getMessage().contains("secret-value"), "diagnostic leaked token value");
        assertTrue(result.getMessage().contains("token=[REDACTED]"), "diagnostic redaction marker");
    }

    private static final class CountingLoader implements ComplianceAuditor.ComplianceOverrideLoader {
        private final ComplianceAuditor.ComplianceOverrideLoadResult result;
        private int loadCount;

        private CountingLoader(ComplianceAuditor.ComplianceOverrideLoadResult result) {
            this.result = result;
        }

        @Override
        public ComplianceAuditor.ComplianceOverrideLoadResult load() {
            loadCount++;
            return result;
        }
    }

    private static final class StubHttpURLConnection extends HttpURLConnection {
        private final byte[] payload;

        private StubHttpURLConnection(URL url, byte[] payload) {
            super(url);
            this.payload = payload;
        }

        @Override
        public void disconnect() {
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() {
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(payload);
        }
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
