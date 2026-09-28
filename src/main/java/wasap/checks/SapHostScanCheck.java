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
 * Host-level active scan check. Registered with {@code ScanCheckType.PER_HOST}
 * so Burp runs it exactly once per host, regardless of how many insertion
 * points are audited. This is what schedules the endpoint-catalog enumeration
 * and the CVE-tied active probes without them re-firing per insertion point.
 * The {@link AuditInsertionPoint} argument is placeholder data for PER_HOST and
 * is not used.
 */
public class SapHostScanCheck implements ActiveScanCheck {

    private final MontoyaApi api;
    private final SapHostChecks hostChecks;

    public SapHostScanCheck(MontoyaApi api) {
        this.api = api;
        this.hostChecks = new SapHostChecks(api);
    }

    @Override
    public String checkName() {
        return "WaSAP SAP host and CVE checks";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, Http http) {
        try {
            return AuditResult.auditResult(hostChecks.runAll(baseRequestResponse, http));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] host checks failed: " + e.getMessage());
            return AuditResult.auditResult(new ArrayList<>());
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return SapIssueConsolidation.consolidate(existingIssue, newIssue);
    }
}
