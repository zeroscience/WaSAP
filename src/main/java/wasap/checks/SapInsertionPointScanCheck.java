package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.util.ArrayList;

/**
 * Insertion-point active scan check. Registered with
 * {@code ScanCheckType.PER_INSERTION_POINT} so Burp runs it once per insertion
 * point, but it only acts on SAP-specific parameter names (see
 * {@link SapInsertionPointChecks}) and stays clear of Burp's built-in
 * XSS / SQLi / traversal auditing.
 */
public class SapInsertionPointScanCheck implements ActiveScanCheck {

    private final MontoyaApi api;
    private final SapInsertionPointChecks insertionPointChecks;

    public SapInsertionPointScanCheck(MontoyaApi api) {
        this.api = api;
        this.insertionPointChecks = new SapInsertionPointChecks(api);
    }

    @Override
    public String checkName() {
        return "WaSAP SAP parameter checks";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, Http http) {
        try {
            return AuditResult.auditResult(insertionPointChecks.run(baseRequestResponse, insertionPoint, http));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] insertion point checks failed: " + e.getMessage());
            return AuditResult.auditResult(new ArrayList<>());
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return SapIssueConsolidation.consolidate(existingIssue, newIssue);
    }
}
