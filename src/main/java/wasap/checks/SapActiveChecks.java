package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class SapActiveChecks {

    private final MontoyaApi api;

    public SapActiveChecks(MontoyaApi api) {
        this.api = api;
    }

    public List<AuditIssue> run(HttpService service, Http http, boolean sapHost) {
        List<AuditIssue> issues = new ArrayList<>();
        addIfNotNull(issues, checkHypR3Xss(service, http));
        addIfNotNull(issues, checkIcmadVulnerableVersion(service, http));
        addIfNotNull(issues, checkVisualComposerMetadataUploader(service, http, sapHost));
        addIfNotNull(issues, checkCtcWebServiceWsdl(service, http));
        addIfNotNull(issues, checkSolManEemAdmin(service, http));
        addIfNotNull(issues, checkSchedulerTraversal(service, http));
        addIfNotNull(issues, checkPublicInfoDisclosure(service, http));
        return issues;
    }

    private void addIfNotNull(List<AuditIssue> list, AuditIssue issue) {
        if (issue != null) {
            list.add(issue);
        }
    }

    /**
     * True when a response carries hallmarks of an SAP stack: an SAP product in
     * the Server header, an SAP-specific response header, or an SAP session
     * cookie. Used to corroborate CVE findings so a bare status code on a
     * non-SAP host does not raise a false positive.
     */
    static boolean hasSapIndicators(HttpResponse response) {
        if (response == null) {
            return false;
        }
        String server = response.headerValue("Server");
        if (server != null) {
            String s = server.toLowerCase();
            if (s.contains("sap netweaver") || s.contains("sap web dispatcher")
                    || s.contains("saprouter") || s.contains("sap internet")) {
                return true;
            }
        }
        for (HttpHeader h : response.headers()) {
            String n = h.name().toLowerCase();
            if (n.startsWith("sap-") || n.startsWith("x-sap-")) {
                return true;
            }
        }
        for (Cookie c : response.cookies()) {
            String cn = c.name();
            if (cn.equals("MYSAPSSO2") || cn.startsWith("SAP_SESSIONID_")
                    || cn.startsWith("saplb_") || cn.equals("sap-usercontext")
                    || cn.equals("PortalAlias")) {
                return true;
            }
        }
        return false;
    }

    private AuditIssue checkHypR3Xss(HttpService service, Http http) {
        String marker = "wasap" + Long.toHexString(System.nanoTime());
        String path = "/HYPARCHIV/HypR3Http.dll?zsl<script>" + marker + "</script>zsl=1";
        HttpRequestResponse rr = send(http, service, path);
        if (rr == null || rr.response() == null) {
            return null;
        }
        String body = rr.response().bodyToString();
        if (body.contains("<script>" + marker + "</script>")) {
            return AuditIssue.auditIssue(
                    "SAP: Reflected XSS in HypR3Http.dll",
                    "<p>The legacy SAP <code>HypR3Http.dll</code> component reflected an injected script payload " +
                            "containing a random marker, indicating a reflected cross-site scripting vulnerability in " +
                            "the HYPARCHIV ICF service.</p>",
                    "Apply the vendor patch and restrict access to HYPARCHIV. Disable the service if unused.",
                    rr.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "<p><code>HypR3Http.dll</code> is part of the SAP ArchiveLink / HYPARCHIV integration and has " +
                            "historically suffered from input-reflection issues.</p>",
                    "Restrict exposure of legacy SAP DLLs to trusted users only.",
                    AuditIssueSeverity.HIGH,
                    rr);
        }
        return null;
    }

    private AuditIssue checkIcmadVulnerableVersion(HttpService service, Http http) {
        HttpRequestResponse rr = send(http, service, "/sap/public/info");
        if (rr == null || rr.response() == null) {
            return null;
        }
        String serverHeader = rr.response().headerValue("Server");
        if (serverHeader == null) {
            return null;
        }
        boolean sapServer = serverHeader.contains("SAP NetWeaver Application Server")
                || serverHeader.contains("SAP Web Dispatcher");
        boolean vulnerableRange = serverHeader.contains("7.22")
                || serverHeader.contains("7.49")
                || serverHeader.contains("7.53")
                || serverHeader.contains("7.77")
                || serverHeader.contains("7.81")
                || serverHeader.contains("7.85")
                || serverHeader.contains("7.86")
                || serverHeader.contains("7.87")
                || serverHeader.contains("7.88");
        if (sapServer && vulnerableRange) {
            return AuditIssue.auditIssue(
                    "SAP: Potentially Vulnerable to ICMAD (CVE-2022-22536)",
                    "<p>The <code>Server</code> header <code>" + escape(serverHeader) + "</code> matches an SAP NetWeaver " +
                            "Application Server / Web Dispatcher version range affected by CVE-2022-22536 (ICMAD). " +
                            "Exploitation permits HTTP request smuggling and memory poisoning against the ICM.</p>",
                    "Apply SAP Security Note 3123396 and restart all affected ICM / Web Dispatcher components.",
                    rr.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.TENTATIVE,
                    "<p>ICMAD is a family of memory-corruption and HTTP-smuggling issues in the SAP Internet " +
                            "Communication Manager (ICM) and Web Dispatcher reported by Onapsis in 2022.</p>",
                    "Upgrade ICM / Web Dispatcher to a fixed patch level.",
                    AuditIssueSeverity.HIGH,
                    rr);
        }
        return null;
    }

    private AuditIssue checkVisualComposerMetadataUploader(HttpService service, Http http, boolean sapHost) {
        HttpRequestResponse rr = send(http, service, "/developmentserver/metadatauploader");
        if (rr == null || rr.response() == null) {
            return null;
        }
        int statusCode = rr.response().statusCode();
        boolean sap = sapHost || hasSapIndicators(rr.response());

        // The metadatauploader servlet answers GET with 200, or 405 when it only
        // accepts POST; either shape (on an SAP host) is a strong signal. A bare
        // 500 is ambiguous and is only considered when the host is corroborated
        // as SAP. Without any SAP corroboration nothing is reported, so a generic
        // server error on an unrelated application does not raise this issue.
        if (!sap) {
            return null;
        }

        AuditIssueConfidence confidence;
        if (statusCode == 200 || statusCode == 405) {
            confidence = AuditIssueConfidence.FIRM;
        } else if (statusCode == 500) {
            confidence = AuditIssueConfidence.TENTATIVE;
        } else {
            return null;
        }

        String detail = "<p>The SAP NetWeaver Visual Composer <code>metadatauploader</code> endpoint is reachable "
                + "(HTTP " + statusCode + ") on a host that fingerprints as SAP. This endpoint was actively "
                + "exploited in 2025 under CVE-2025-31324 to upload arbitrary files, including JSP web shells, "
                + "leading to unauthenticated remote code execution.</p>"
                + (confidence == AuditIssueConfidence.TENTATIVE
                        ? "<p>The endpoint returned HTTP 500, which can indicate the servlet is present but errored. "
                        + "Confirm the component is Visual Composer (VCFRAMEWORK) and test the upload manually before "
                        + "treating this as exploitable.</p>"
                        : "");

        return AuditIssue.auditIssue(
                "SAP: Visual Composer Metadata Uploader Exposed (CVE-2025-31324)",
                detail,
                "Apply SAP Security Note 3594142 immediately. If Visual Composer is not required, disable the " +
                        "<code>VCFRAMEWORK</code> development component and block this endpoint at the Web Dispatcher.",
                rr.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                "<p>CVE-2025-31324 is a critical unauthenticated file-upload vulnerability in SAP NetWeaver " +
                        "Visual Composer, actively exploited since April 2025. The same " +
                        "<code>metadatauploader</code> endpoint is also the vector for the chained insecure " +
                        "deserialization flaw CVE-2025-42999, so apply the latest SAP Security Notes covering both.</p>",
                "Patch immediately and review the filesystem for dropped JSP / WAR artefacts.",
                AuditIssueSeverity.HIGH,
                rr);
    }

    // CVE-2020-6207: SAP Solution Manager (SolMan) missing-authentication check
    // in the EEM / End-user Experience Monitoring administration service. The
    // WSDL is content-verified so this does not fire on unrelated hosts.
    private AuditIssue checkSolManEemAdmin(HttpService service, Http http) {
        HttpRequestResponse rr = send(http, service, "/EemAdminService/EemAdmin?wsdl");
        if (rr == null || rr.response() == null) {
            return null;
        }
        if (rr.response().statusCode() != 200) {
            return null;
        }
        String body = rr.response().bodyToString();
        boolean looksLikeEem = body.contains("EemAdmin") && (body.contains("wsdl") || body.contains("<definitions"));
        if (!looksLikeEem) {
            return null;
        }
        return AuditIssue.auditIssue(
                "SAP: Solution Manager EEM Admin Service Exposed (CVE-2020-6207)",
                "<p>The SAP Solution Manager <code>EemAdminService</code> WSDL is reachable without authentication. " +
                        "CVE-2020-6207 is a missing-authentication-check vulnerability in the SolMan EEM component that " +
                        "allows an unauthenticated attacker to administer connected SMD agents, leading to full " +
                        "compromise of the managed SAP landscape.</p>",
                "Apply SAP Security Note 2890213 and restrict access to the Solution Manager EEM services.",
                rr.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "<p>CVE-2020-6207 affects SAP Solution Manager (user-experience monitoring, EEM). It was disclosed in " +
                        "2020 and public exploit code exists.</p>",
                "Patch and block external exposure of Solution Manager management services.",
                AuditIssueSeverity.HIGH,
                rr);
    }

    private AuditIssue checkCtcWebServiceWsdl(HttpService service, Http http) {
        HttpRequestResponse rr = send(http, service, "/CTCWebService/CTCWebServiceBean?wsdl");
        if (rr == null || rr.response() == null) {
            return null;
        }
        int statusCode = rr.response().statusCode();
        String body = rr.response().bodyToString();
        if (statusCode == 200 && body.contains("wsdl") && body.contains("CTC")) {
            return AuditIssue.auditIssue(
                    "SAP: CTC WebService WSDL Exposed (CVE-2020-6287 / RECON)",
                    "<p>The SAP LM Configuration Wizard <code>CTCWebService</code> WSDL is exposed without " +
                            "authentication. This is the attack surface exploited by CVE-2020-6287 ('RECON'), which " +
                            "allows creation of administrative users on the SAP NetWeaver Java engine.</p>",
                    "Apply SAP Security Note 2934135 and restrict access to the LM Configuration Wizard.",
                    rr.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "<p>CVE-2020-6287 (RECON) is a critical authentication-bypass vulnerability in the SAP NetWeaver " +
                            "AS Java LM Configuration Wizard disclosed in July 2020.</p>",
                    "Patch and block external exposure.",
                    AuditIssueSeverity.HIGH,
                    rr);
        }
        return null;
    }

    // CVE-2017-12637: SAP NetWeaver AS Java directory traversal in the Scheduler
    // (com.sap.engine.heartbeat) component. The finding is confirmed only when the
    // traversal actually returns the application's WEB-INF/web.xml, so it is fully
    // content-verified and will not fire on an unrelated host.
    private AuditIssue checkSchedulerTraversal(HttpService service, Http http) {
        String rawPath = "/scheduler/ui/js/ffffffffbca41eda/common/"
                + "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/WEB-INF/web.xml";
        HttpRequestResponse rr = sendRawPath(http, service, rawPath);
        if (rr == null || rr.response() == null) {
            return null;
        }
        if (rr.response().statusCode() != 200) {
            return null;
        }
        String body = rr.response().bodyToString();
        String lower = body.toLowerCase();
        boolean isWebXml = lower.contains("<web-app") || lower.contains("</web-app>")
                || (lower.contains("<servlet") && lower.contains("web-app"));
        if (!isWebXml) {
            return null;
        }
        return AuditIssue.auditIssue(
                "SAP: NetWeaver AS Java Scheduler Directory Traversal (CVE-2017-12637)",
                "<p>A directory traversal through the SAP NetWeaver AS Java Scheduler component returned the " +
                        "application's <code>WEB-INF/web.xml</code> deployment descriptor. CVE-2017-12637 allows an " +
                        "unauthenticated attacker to read arbitrary files from the server filesystem, including " +
                        "configuration and secret stores.</p>",
                "Apply SAP Security Note 2486657 and restrict access to the Scheduler component.",
                rr.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "<p>CVE-2017-12637 is a directory traversal in the SAP NetWeaver AS Java Scheduler, disclosed in 2017 " +
                        "with public exploit code.</p>",
                "Patch and restrict filesystem-exposing components.",
                AuditIssueSeverity.HIGH,
                rr);
    }

    private AuditIssue checkPublicInfoDisclosure(HttpService service, Http http) {
        HttpRequestResponse rr = send(http, service, "/sap/public/info");
        if (rr == null || rr.response() == null) {
            return null;
        }
        if (rr.response().statusCode() != 200) {
            return null;
        }
        String body = rr.response().bodyToString();
        boolean looksLikeInfo = body.contains("<rfcSI_EXPORT>")
                || body.contains("RFCSI_EXPORT")
                || (body.contains("SYSID") && body.contains("DBHOST"))
                || body.contains("RFC_SYSTEM_INFO");
        if (!looksLikeInfo) {
            return null;
        }

        String extracted = extractSystemInfo(body);
        String detail = "<p>The <code>/sap/public/info</code> service returned SAP system metadata without " +
                "authentication. This information substantially lowers the effort required for targeted " +
                "exploitation (mapping the host to known SAP Security Notes, database attacks, and RFC abuse).</p>"
                + extracted;

        return AuditIssue.auditIssue(
                "SAP: Unauthenticated System Information Disclosure (/sap/public/info)",
                detail,
                "Disable the <code>/sap/public/info</code> service via transaction SICF or restrict it to internal " +
                        "networks at the Web Dispatcher.",
                rr.request().url(),
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.FIRM,
                "<p>On default NetWeaver installations the <code>/sap/public/info</code> ICF node returns an XML " +
                        "document describing the system. SAP recommends restricting the service on production systems.</p>",
                "Restrict or disable the public info service.",
                AuditIssueSeverity.MEDIUM,
                rr);
    }

    // Pull the interesting fields out of the /sap/public/info XML (RFC_SYSTEM_INFO
    // structure) so the reported issue shows exactly what the host disclosed.
    private String extractSystemInfo(String body) {
        String[][] fields = {
                {"RFCSYSID", "System ID (SID)"},
                {"RFCDBSYS", "Database system"},
                {"RFCDBHOST", "Database host"},
                {"RFCSAPRL", "SAP kernel release"},
                {"RFCKERNRL", "Kernel patch level"},
                {"RFCOPSYS", "Operating system"},
                {"RFCHOST", "Application host"},
                {"RFCIPADDR", "IP address"},
                {"RFCMACH", "Machine ID"}
        };
        StringBuilder sb = new StringBuilder();
        for (String[] f : fields) {
            String value = tagValue(body, f[0]);
            if (value != null && !value.isEmpty()) {
                sb.append("<li><b>").append(f[1]).append(":</b> <code>")
                        .append(escape(value)).append("</code></li>");
            }
        }
        if (sb.length() == 0) {
            return "";
        }
        return "<p>Fields disclosed by this host:</p><ul>" + sb + "</ul>";
    }

    // Returns the text between <TAG>...</TAG> (case-insensitive), or null.
    private static String tagValue(String body, String tag) {
        String lower = body.toLowerCase();
        String open = "<" + tag.toLowerCase() + ">";
        String close = "</" + tag.toLowerCase() + ">";
        int start = lower.indexOf(open);
        if (start < 0) {
            return null;
        }
        start += open.length();
        int end = lower.indexOf(close, start);
        if (end < 0 || end - start > 128) {
            return null;
        }
        return body.substring(start, end).trim();
    }

    private HttpRequestResponse send(Http http, HttpService svc, String path) {
        try {
            String proto = svc.secure() ? "https" : "http";
            int port = svc.port();
            boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
            String url = proto + "://" + svc.host() + (defaultPort ? "" : ":" + port) + path;
            return http.sendRequest(HttpRequest.httpRequestFromUrl(url));
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] send error: " + e.getMessage());
            return null;
        }
    }

    // Sends a request whose path is set verbatim via withPath(), so a percent
    // encoded traversal sequence is transmitted literally rather than being
    // normalised away by URL parsing.
    private HttpRequestResponse sendRawPath(Http http, HttpService svc, String rawPath) {
        try {
            String proto = svc.secure() ? "https" : "http";
            int port = svc.port();
            boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
            String base = proto + "://" + svc.host() + (defaultPort ? "" : ":" + port) + "/";
            HttpRequest req = HttpRequest.httpRequestFromUrl(base).withPath(rawPath);
            return http.sendRequest(req);
        } catch (Exception e) {
            api.logging().logToError("[WaSAP] send error: " + e.getMessage());
            return null;
        }
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
