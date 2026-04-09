package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SapInsertionPointChecks {

    private static final Set<String> SAP_PARAMS = new HashSet<>(Arrays.asList(
            "sap-client",
            "sap-language",
            "sap-user",
            "sap-syscmd",
            "sap-sessioncmd",
            "sap-contextid",
            "sap-locale",
            "sap-login-locale",
            "sap-accessibility",
            "sap-ssc"
    ));

    private final MontoyaApi api;

    public SapInsertionPointChecks(MontoyaApi api) {
        this.api = api;
    }

    public List<AuditIssue> run(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        String rawName = insertionPoint.name();
        if (rawName == null) {
            return issues;
        }
        String paramName = rawName.toLowerCase();
        if (!SAP_PARAMS.contains(paramName)) {
            return issues;
        }

        String payload;
        switch (paramName) {
            case "sap-client":
                payload = "99999";
                break;
            case "sap-language":
            case "sap-locale":
            case "sap-login-locale":
                payload = "ZZ";
                break;
            case "sap-user":
                payload = "wasap-nonexistent-" + Long.toHexString(System.nanoTime());
                break;
            default:
                payload = "wasap" + Long.toHexString(System.nanoTime());
                break;
        }

        HttpRequest probe = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
        HttpRequestResponse rr = api.http().sendRequest(probe);
        if (rr == null || rr.response() == null) {
            return issues;
        }
        String body = rr.response().bodyToString();

        boolean sapError = body.contains("ABAP runtime error")
                || body.contains("ABAP Runtime Error")
                || body.contains("com.sap.engine.")
                || body.contains("SAP System Information")
                || body.contains("The error occurred while")
                || (body.contains("Client") && body.contains("is not available"))
                || body.contains("Language not installed");

        if (sapError) {
            issues.add(AuditIssue.auditIssue(
                    "SAP: Error Disclosure via " + rawName,
                    "<p>Injecting the value <code>" + escape(payload) + "</code> into the SAP-specific parameter "
                            + "<code>" + escape(rawName) + "</code> produced an SAP runtime error containing "
                            + "internal diagnostic information.</p>",
                    "Return generic error pages for unexpected parameter values. Validate SAP request parameters " +
                            "at the Web Dispatcher and disable full error pages in the ICM configuration.",
                    base.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    "<p>SAP-specific request parameters such as <code>sap-client</code>, <code>sap-language</code>, " +
                            "and <code>sap-user</code> influence the backend client/locale selection on the ABAP " +
                            "stack. Invalid values often produce highly verbose diagnostic pages.</p>",
                    "",
                    AuditIssueSeverity.LOW,
                    rr));
        }

        return issues;
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
