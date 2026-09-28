package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import java.util.ArrayList;

/**
 * Passive scan check. Registered with {@code ScanCheckType.PER_REQUEST}: Burp
 * invokes it once per audited request/response, and it must not issue new HTTP
 * requests. Wraps {@link SapPassiveChecks} (SAP fingerprints, cookie flags,
 * verbose error disclosure).
 */
public class SapPassiveScanCheck implements PassiveScanCheck {

    private final MontoyaApi api;
    private final SapPassiveChecks passiveChecks;

    public SapPassiveScanCheck(MontoyaApi api) {
        this.api = api;
        this.passiveChecks = new SapPassiveChecks(api);
    }

    @Override
    public String checkName() {
        return "WaSAP SAP passive checks";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        try {
            return AuditResult.auditResult(passiveChecks.run(baseRequestResponse));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] passive checks failed: " + e.getMessage());
            return AuditResult.auditResult(new ArrayList<>());
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return SapIssueConsolidation.consolidate(existingIssue, newIssue);
    }
}
