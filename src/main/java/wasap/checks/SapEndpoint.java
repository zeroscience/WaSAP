package wasap.checks;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public final class SapEndpoint {
    public final String path;
    public final String title;
    public final String category;
    public final AuditIssueSeverity severity;
    public final String cve;
    public final String detail;
    public final String remediation;

    public SapEndpoint(String path, String title, String category,
                       AuditIssueSeverity severity, String cve,
                       String detail, String remediation) {
        this.path = path;
        this.title = title;
        this.category = category;
        this.severity = severity;
        this.cve = cve;
        this.detail = detail;
        this.remediation = remediation;
    }
}
