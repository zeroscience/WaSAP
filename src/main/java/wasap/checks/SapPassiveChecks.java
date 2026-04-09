package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class SapPassiveChecks {

    private final MontoyaApi api;

    public SapPassiveChecks(MontoyaApi api) {
        this.api = api;
    }

    public List<AuditIssue> run(HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpResponse response = base.response();
        if (response == null) {
            return issues;
        }

        String body = response.bodyToString();
        String url = base.request().url();

        if (body.contains("sap-ui-core.js") || body.contains("sap.ui.version")) {
            String version = extractVersion(body);
            issues.add(AuditIssue.auditIssue(
                    "SAP: UI5 Framework Detected",
                    "<p>This resource references SAP UI5 framework assets"
                            + (version != null ? " (version <code>" + escape(version) + "</code>)" : "")
                            + ". This positively fingerprints the application as an SAP UI5 front-end.</p>",
                    "Ensure the deployed SAP UI5 runtime is a supported, patched version.",
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM,
                    "<p>SAP UI5 / OpenUI5 is the client-side framework used by Fiori and many custom SAP UIs.</p>",
                    "",
                    AuditIssueSeverity.INFORMATION,
                    base));
        }

        for (HttpHeader h : response.headers()) {
            String name = h.name();
            String value = h.value();

            if (name.equalsIgnoreCase("Server") && value.contains("SAP NetWeaver Application Server")) {
                issues.add(AuditIssue.auditIssue(
                        "SAP: NetWeaver Server Header Disclosure",
                        "<p>The server advertises itself as <code>" + escape(value) + "</code>. Version disclosure " +
                                "assists an attacker in mapping the host to known SAP Security Notes.</p>",
                        "Strip or normalise the <code>Server</code> response header at the Web Dispatcher or reverse proxy.",
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.CERTAIN,
                        "<p>SAP NetWeaver exposes its product name and patch level via the <code>Server</code> header " +
                                "by default.</p>",
                        "Suppress version tokens in HTTP responses.",
                        AuditIssueSeverity.INFORMATION,
                        base));
            }

            String lname = name.toLowerCase();
            if (lname.equals("x-sap-page-generation")
                    || lname.equals("sap-server")
                    || lname.equals("sap-perf-fesrec")
                    || lname.equals("x-sap-login-page")
                    || lname.equals("sap-usercontext")) {
                issues.add(AuditIssue.auditIssue(
                        "SAP: Product-Specific Header Disclosure",
                        "<p>The response contains the SAP-specific header <code>" + escape(name) + ": "
                                + escape(value) + "</code>, fingerprinting the host as an SAP component.</p>",
                        "Strip SAP-specific headers at the perimeter.",
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.CERTAIN,
                        "<p>SAP products add proprietary response headers that uniquely identify the stack.</p>",
                        "",
                        AuditIssueSeverity.INFORMATION,
                        base));
            }
        }

        for (Cookie cookie : response.cookies()) {
            String cname = cookie.name();
            boolean isSapCookie = cname.equals("MYSAPSSO2")
                    || cname.startsWith("SAP_SESSIONID_")
                    || cname.equals("PortalAlias")
                    || cname.startsWith("saplb_")
                    || cname.equals("sap-usercontext")
                    || cname.equals("sap-login-XSRF");
            if (!isSapCookie) {
                continue;
            }

            String raw = rawSetCookie(response, cname);
            if (raw == null) {
                continue;
            }
            String lower = raw.toLowerCase();
            boolean httpOnly = lower.contains("httponly");
            boolean secure = lower.contains("secure");

            if (!httpOnly || !secure) {
                StringBuilder detail = new StringBuilder();
                detail.append("<p>The SAP session cookie <code>").append(escape(cname))
                        .append("</code> was set without the following security flags:</p><ul>");
                if (!httpOnly) {
                    detail.append("<li><code>HttpOnly</code></li>");
                }
                if (!secure) {
                    detail.append("<li><code>Secure</code></li>");
                }
                detail.append("</ul><p>SAP session cookies grant access to authenticated SAP sessions; missing " +
                        "protection flags significantly increase the impact of any XSS or MITM position.</p>");

                issues.add(AuditIssue.auditIssue(
                        "SAP: Session Cookie Missing Security Flags (" + cname + ")",
                        detail.toString(),
                        "Set <code>HttpOnly</code> and <code>Secure</code> on all SAP session cookies. For the ABAP " +
                                "stack, configure profile parameters <code>icf/set_HTTPonly_flag_on_cookies=0</code> " +
                                "and <code>login/ticket_only_by_https=1</code>.",
                        url,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.CERTAIN,
                        "<p>SAP cookies such as <code>MYSAPSSO2</code> and <code>SAP_SESSIONID_*</code> carry " +
                                "authentication state and must be protected against theft.</p>",
                        "",
                        AuditIssueSeverity.MEDIUM,
                        base));
            }
        }

        boolean abapError = body.contains("ABAP runtime error") || body.contains("ABAP Runtime Error");
        boolean j2eeError = body.contains("com.sap.engine.") || body.contains("Full Exception Chain");
        boolean genericSapError = body.contains("SAP Web Application Server") && body.contains("Error");
        if (abapError || j2eeError || genericSapError) {
            issues.add(AuditIssue.auditIssue(
                    "SAP: Verbose Error Disclosure",
                    "<p>The response contains an SAP NetWeaver / ABAP verbose error message. These pages typically " +
                            "expose internal stack traces, source code paths, and system identifiers that help an " +
                            "attacker profile the host.</p>",
                    "Configure the ICM / Web Dispatcher to return generic error pages and disable detailed stack " +
                            "traces via profile parameter <code>service/error_page=generic</code>.",
                    url,
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    "<p>ABAP and J2EE runtimes emit highly verbose error pages by default.</p>",
                    "",
                    AuditIssueSeverity.LOW,
                    base));
        }

        return issues;
    }

    private String rawSetCookie(HttpResponse response, String cookieName) {
        for (HttpHeader h : response.headers()) {
            if (h.name().equalsIgnoreCase("Set-Cookie") && h.value().startsWith(cookieName + "=")) {
                return h.value();
            }
        }
        return null;
    }

    private String extractVersion(String body) {
        try {
            int idx = body.indexOf("sap-ui-version");
            if (idx < 0) {
                idx = body.indexOf("sap.ui.version");
            }
            if (idx < 0) {
                return null;
            }
            int eq = body.indexOf('=', idx);
            if (eq < 0) {
                return null;
            }
            int end = eq + 1;
            int max = Math.min(body.length(), eq + 16);
            while (end < max) {
                char c = body.charAt(end);
                if (!Character.isDigit(c) && c != '.' && c != '-' && c != 'B' && c != 'S' && c != 'P') {
                    break;
                }
                end++;
            }
            return eq + 1 < end ? body.substring(eq + 1, end) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
