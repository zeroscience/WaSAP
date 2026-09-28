package wasap.checks;

import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

/**
 * Shared issue-consolidation logic for the WaSAP scan checks. Two issues are
 * treated as duplicates when they share both name and base URL, in which case
 * the existing one is kept; otherwise both are reported.
 */
final class SapIssueConsolidation {

    private SapIssueConsolidation() {
    }

    static ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        boolean sameName = newIssue.name().equals(existingIssue.name());
        boolean sameUrl = newIssue.baseUrl().equals(existingIssue.baseUrl());
        if (sameName && sameUrl) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
