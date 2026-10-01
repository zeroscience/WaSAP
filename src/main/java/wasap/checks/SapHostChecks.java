package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
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

    // Requests are issued through the scan-task's Http object so Burp links them
    // to the current audit (throttling, scope, logging).
    public List<AuditIssue> runAll(HttpRequestResponse base, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpService service = base.httpService();

        // Corroborate that this is actually an SAP host before raising endpoint
        // findings. The passive side already saw the base response; combine that
        // with a couple of targeted probes. On a non-SAP host this stays false
        // and each endpoint must prove SAP on its own response, which suppresses
        // false positives on unrelated applications.
        boolean sapHost = SapActiveChecks.hasSapIndicators(base.response()) || looksLikeSapHost(service, http);

        Baseline baseline = computeBaseline(service, http);

        for (SapEndpoint endpoint : SapEndpointCatalog.ENDPOINTS) {
            try {
                AuditIssue issue = probeEndpoint(service, endpoint, baseline, http, sapHost);
                if (issue != null) {
                    issues.add(issue);
                }
            } catch (Exception e) {
                api.logging().logToError("[WaSAP] probe error " + endpoint.path + ": " + e.getMessage());
            }
        }

        issues.addAll(activeChecks.run(service, http, sapHost));
        return issues;
    }

    // Lightweight SAP host fingerprint: look for SAP indicators on the root page
    // and on the SAP-specific /sap/public/info service (whose body is checked so
    // a catch-all 200 does not count).
    private boolean looksLikeSapHost(HttpService service, Http http) {
        try {
            HttpRequestResponse root = http.sendRequest(HttpRequest.httpRequestFromUrl(buildUrl(service, "/")));
            if (root != null && SapActiveChecks.hasSapIndicators(root.response())) {
                return true;
            }
        } catch (Exception ignored) {
        }
        try {
            HttpRequestResponse info = http.sendRequest(
                    HttpRequest.httpRequestFromUrl(buildUrl(service, "/sap/public/info")));
            if (info != null && info.response() != null) {
                if (SapActiveChecks.hasSapIndicators(info.response())) {
                    return true;
                }
                String body = info.response().bodyToString();
                if (info.response().statusCode() == 200
                        && (body.contains("RFC_SYSTEM_INFO") || body.contains("RFCSI_EXPORT")
                                || (body.contains("SYSID") && body.contains("DBHOST")))) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private Baseline computeBaseline(HttpService service, Http http) {
        try {
            String random = "/wasap-probe-" + Long.toHexString(System.nanoTime());
            HttpRequestResponse rr = http.sendRequest(HttpRequest.httpRequestFromUrl(buildUrl(service, random)));
            if (rr != null && rr.response() != null) {
                return new Baseline(rr.response().statusCode(), rr.response().body().length());
            }
        } catch (Exception ignored) {
        }
        return new Baseline(-1, -1);
    }

    private AuditIssue probeEndpoint(HttpService service, SapEndpoint endpoint, Baseline baseline, Http http,
                                     boolean sapHost) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(buildUrl(service, endpoint.path));
        HttpRequestResponse rr = http.sendRequest(req);
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

        // Only report when there is SAP corroboration: either the host already
        // fingerprinted as SAP, or this specific response carries SAP markers.
        // This prevents a reachable but generic path on a non-SAP application
        // from raising an "SAP:" issue.
        if (!sapHost && !SapActiveChecks.hasSapIndicators(rr.response())) {
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
