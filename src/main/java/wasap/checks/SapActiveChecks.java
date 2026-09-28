package wasap.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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

    public List<AuditIssue> run(HttpService service, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        addIfNotNull(issues, checkHypR3Xss(service, http));
        addIfNotNull(issues, checkIcmadVulnerableVersion(service, http));
        addIfNotNull(issues, checkVisualComposerMetadataUploader(service, http));
        addIfNotNull(issues, checkCtcWebServiceWsdl(service, http));
        addIfNotNull(issues, checkPublicInfoDisclosure(service, http));
        return issues;
    }

    private void addIfNotNull(List<AuditIssue> list, AuditIssue issue) {
        if (issue != null) {
            list.add(issue);
        }
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

    private AuditIssue checkVisualComposerMetadataUploader(HttpService service, Http http) {
        HttpRequestResponse rr = send(http, service, "/developmentserver/metadatauploader");
        if (rr == null || rr.response() == null) {
            return null;
        }
        int statusCode = rr.response().statusCode();
        if (statusCode == 200 || statusCode == 405 || statusCode == 500) {
            return AuditIssue.auditIssue(
                    "SAP: Visual Composer Metadata Uploader Exposed (CVE-2025-31324)",
                    "<p>The SAP NetWeaver Visual Composer <code>metadatauploader</code> endpoint is reachable " +
                            "(HTTP " + statusCode + "). This endpoint was actively exploited in 2025 under " +
                            "CVE-2025-31324 to upload arbitrary files, including JSP web shells, leading to " +
                            "unauthenticated remote code execution.</p>",
                    "Apply SAP Security Note 3594142 immediately. If Visual Composer is not required, disable the " +
                            "<code>VCFRAMEWORK</code> development component and block this endpoint at the Web Dispatcher.",
                    rr.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.TENTATIVE,
                    "<p>CVE-2025-31324 is a critical unauthenticated file-upload vulnerability in SAP NetWeaver " +
                            "Visual Composer, actively exploited since April 2025.</p>",
                    "Patch immediately and review the filesystem for dropped JSP / WAR artefacts.",
                    AuditIssueSeverity.HIGH,
                    rr);
        }
        return null;
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

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
