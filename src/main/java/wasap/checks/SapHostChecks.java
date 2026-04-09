package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import java.util.ArrayList;
import java.util.List;

public class SapHostChecks {

    private final MontoyaApi api;
    private final SapActiveChecks activeChecks;

    public SapHostChecks(MontoyaApi api) {
        this.api = api;
        this.activeChecks = new SapActiveChecks(api);
    }

    public List<AuditIssue> runAll(HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpService service = base.httpService();

        Baseline baseline = computeBaseline(service);

        for (SapEndpoint endpoint : SapEndpointCatalog.ENDPOINTS) {
            try {
                AuditIssue issue = probeEndpoint(service, endpoint, baseline);
                if (issue != null) {
                    issues.add(issue);
                }
            } catch (Exception e) {
                api.logging().logToError("[WaSAP] probe error " + endpoint.path + ": " + e.getMessage());
            }
        }

        issues.addAll(activeChecks.run(service));
        return issues;
    }

    private Baseline computeBaseline(HttpService service) {
        try {
            String random = "/wasap-probe-" + Long.toHexString(System.nanoTime());
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(buildUrl(service, random)));
            if (rr != null && rr.response() != null) {
                return new Baseline(rr.response().statusCode(), rr.response().body().length());
            }
        } catch (Exception ignored) {
        }
        return new Baseline(-1, -1);
    }

    private AuditIssue probeEndpoint(HttpService service, SapEndpoint endpoint, Baseline baseline) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(buildUrl(service, endpoint.path));
        HttpRequestResponse rr = api.http().sendRequest(req);
        if (rr == null || rr.response() == null) {
            return null;
        }

        int statusCode = rr.response().statusCode();
        int length = rr.response().body().length();

        if (statusCode == 404 || statusCode == 400) {
            return null;
        }

        if (baseline.status > 0
                && statusCode == baseline.status
                && Math.abs(length - baseline.length) < 32) {
            return null;
        }

        AuditIssueConfidence confidence;
        if (statusCode == 200) {
            confidence = AuditIssueConfidence.FIRM;
        } else if (statusCode == 401 || statusCode == 403 || statusCode == 405) {
            confidence = AuditIssueConfidence.TENTATIVE;
        } else {
            confidence = AuditIssueConfidence.TENTATIVE;
        }

        String detail = buildDetail(endpoint, statusCode, length);
        String background = buildBackground(endpoint);
        String remediationBackground =
                "Restrict access to SAP administrative and infrastructure endpoints. Enforce authentication and " +
                        "network-level controls, and disable unused ICF services via transaction SICF. On the J2EE " +
                        "stack, restrict administrative URLs via the Web Dispatcher.";

        return AuditIssue.auditIssue(
                "SAP: " + endpoint.title,
                detail,
                endpoint.remediation,
                rr.request().url(),
                endpoint.severity,
                confidence,
                background,
                remediationBackground,
                endpoint.severity,
                rr);
    }

    private String buildUrl(HttpService svc, String path) {
        String proto = svc.secure() ? "https" : "http";
        int port = svc.port();
        boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
        return proto + "://" + svc.host() + (defaultPort ? "" : ":" + port) + path;
    }

    private String buildDetail(SapEndpoint endpoint, int status, int length) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>WaSAP identified a known SAP endpoint exposed on this host.</p>");
        sb.append("<ul>");
        sb.append("<li><b>Path:</b> ").append(htmlEscape(endpoint.path)).append("</li>");
        sb.append("<li><b>Category:</b> ").append(htmlEscape(endpoint.category)).append("</li>");
        sb.append("<li><b>HTTP status:</b> ").append(status).append("</li>");
        sb.append("<li><b>Response length:</b> ").append(length).append("</li>");
        if (endpoint.cve != null) {
            sb.append("<li><b>Associated CVE:</b> ").append(htmlEscape(endpoint.cve)).append("</li>");
        }
        sb.append("</ul>");
        sb.append("<p>").append(endpoint.detail).append("</p>");
        if (status == 401 || status == 403) {
            sb.append("<p>The endpoint is present but authentication is required. Verify that only authorised " +
                    "administrators can reach this service and that no default credentials are in place.</p>");
        }
        return sb.toString();
    }

    private String buildBackground(SapEndpoint endpoint) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>SAP NetWeaver, HANA and Fiori platforms ship with a large number of default HTTP services " +
                "exposed via the Internet Communication Framework (ICF) and the J2EE engine. Many of these services " +
                "are only intended for internal administration but are commonly found on Internet-facing hosts.</p>");
        if (endpoint.cve != null) {
            sb.append("<p>This endpoint has been associated with <b>").append(htmlEscape(endpoint.cve))
                    .append("</b>. Confirm the affected component version and apply the relevant SAP Security Note.</p>");
        }
        return sb.toString();
    }

    private static String htmlEscape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static final class Baseline {
        final int status;
        final int length;

        Baseline(int status, int length) {
            this.status = status;
            this.length = length;
        }
    }
}
