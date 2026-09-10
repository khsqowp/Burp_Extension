package proxyscanner.burpext;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Map;

/**
 * Converts a Security Toolkit Finding (spec §61 standardized shape) into a
 * real Burp Issue (spec §66 item 34: "Scanner Result -> Burp Extension ->
 * Burp Issue") via {@code api.siteMap().add(AuditIssue)} -- confirmed
 * against the real montoya-api 2025.5 jar (javap), not guessed from memory.
 */
final class BurpIssueReporter {
    private final MontoyaApi api;

    BurpIssueReporter(MontoyaApi api) {
        this.api = api;
    }

    /** Returns true if the finding was successfully registered as a Burp
     * Issue. A malformed/unexpected finding shape is logged and skipped --
     * one bad Finding must never abort reporting the rest (same "one
     * failure doesn't take down the whole flow" principle as spec §58). */
    boolean report(Map<String, Object> finding) {
        try {
            String name = stringOrDefault(finding.get("finding"), "Security Toolkit Finding");
            String scanner = stringOrDefault(finding.get("scanner"), "security-toolkit");
            String evidence = stringOrDefault(finding.get("evidence"), "");
            String host = stringOrDefault(finding.get("host"), "");
            String target = stringOrDefault(finding.get("target"), "");

            AuditIssueSeverity severity = mapSeverity((String) finding.get("severity"));
            String baseUrl = resolveBaseUrl(target, host);
            String detail = "<p>Detected by Security Toolkit module: <b>" + escapeHtml(scanner) + "</b></p>"
                    + (evidence.isEmpty() ? "" : "<p>" + escapeHtml(evidence) + "</p>");

            AuditIssue issue = AuditIssue.auditIssue(
                    name, detail, "", baseUrl, severity, AuditIssueConfidence.FIRM,
                    "", "", severity
            );
            api.siteMap().add(issue);
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to report a Security Toolkit finding as a Burp issue", e);
            return false;
        }
    }

    private static String resolveBaseUrl(String target, String host) {
        if (!target.isEmpty() && (target.startsWith("http://") || target.startsWith("https://"))) {
            return target;
        }
        String h = !host.isEmpty() ? host : target;
        return h.isEmpty() ? "http://unknown" : "http://" + h;
    }

    private static AuditIssueSeverity mapSeverity(String severity) {
        if (severity == null) {
            return AuditIssueSeverity.INFORMATION;
        }
        switch (severity.toLowerCase(java.util.Locale.ROOT)) {
            case "high": return AuditIssueSeverity.HIGH;
            case "medium": return AuditIssueSeverity.MEDIUM;
            case "low": return AuditIssueSeverity.LOW;
            default: return AuditIssueSeverity.INFORMATION;
        }
    }

    private static String stringOrDefault(Object value, String fallback) {
        return value instanceof String ? (String) value : fallback;
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
