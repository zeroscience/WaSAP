package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class SapScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final SapHostChecks hostChecks;
    private final SapPassiveChecks passiveChecks;
    private final SapInsertionPointChecks insertionPointChecks;

    private final Set<String> enumeratedHosts = ConcurrentHashMap.newKeySet();

    public SapScanCheck(MontoyaApi api) {
        this.api = api;
        this.hostChecks = new SapHostChecks(api);
        this.passiveChecks = new SapPassiveChecks(api);
        this.insertionPointChecks = new SapInsertionPointChecks(api);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        String hostKey = baseRequestResponse.httpService().host() + ":" + baseRequestResponse.httpService().port();
        if (enumeratedHosts.add(hostKey)) {
            try {
                issues.addAll(hostChecks.runAll(baseRequestResponse));
            } catch (Exception e) {
                api.logging().logToError("[WaSAP] host checks failed for " + hostKey + ": " + e.getMessage());
            }
        }

        try {
            issues.addAll(insertionPointChecks.run(baseRequestResponse, auditInsertionPoint));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] insertion point checks failed: " + e.getMessage());
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        try {
            return AuditResult.auditResult(passiveChecks.run(baseRequestResponse));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] passive checks failed: " + e.getMessage());
            return AuditResult.auditResult(new ArrayList<>());
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        boolean sameName = newIssue.name().equals(existingIssue.name());
        boolean sameUrl = newIssue.baseUrl().equals(existingIssue.baseUrl());
        if (sameName && sameUrl) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
