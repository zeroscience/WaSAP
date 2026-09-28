package wasap.checks;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;

/**
 * Static catalog of well-known SAP HTTP endpoints probed by {@link SapHostChecks}.
 *
 * Each {@link SapEndpoint} carries the fields consumed by
 * {@link SapHostChecks#probeEndpoint}: path, title, category, severity, an
 * optional CVE reference, a detail paragraph and remediation guidance.
 *
 * Entries are intentionally SAP-specific: default ICF/BSP/Web Dynpro services,
 * NetWeaver Java management consoles, Fiori/Gateway OData services, HANA XS
 * tooling, Enterprise Portal, BW/BI and CVE-tied attack surfaces. Generic paths
 * are deliberately excluded so the check adds SAP knowledge on top of Burp's
 * native content-discovery rather than duplicating it.
 */
public final class SapEndpointCatalog {

    private SapEndpointCatalog() {
    }

    // Shared, category-level remediation guidance.
    private static final String REM_ICF =
            "Disable unused ICF services via transaction SICF and restrict the remainder to authenticated, " +
                    "trusted users. Front the host with the Web Dispatcher and block administrative paths at the perimeter.";
    private static final String REM_JAVA =
            "Restrict NetWeaver AS Java management interfaces to a trusted administration network, enforce strong " +
                    "authentication, and remove default/demo content from production systems.";
    private static final String REM_HANA =
            "Restrict HANA XS tooling to trusted developers and administrators, disable it in production, and ensure " +
                    "the XS engine is patched to a current revision.";
    private static final String REM_GATEWAY =
            "Restrict SAP Gateway / OData catalog and management services to authenticated users and review the set " +
                    "of activated (published) OData services.";
    private static final String REM_PORTAL =
            "Restrict Enterprise Portal access to trusted networks and review anonymous / self-registration content.";

    public static final List<SapEndpoint> ENDPOINTS;

    static {
        List<SapEndpoint> e = new ArrayList<>();

        // ---------------------------------------------------------------
        // CVE-tied attack surfaces (high value differentiators)
        // ---------------------------------------------------------------
        e.add(cve("/developmentserver/metadatauploader", "Visual Composer Metadata Uploader",
                HIGH, "CVE-2025-31324",
                "The NetWeaver Visual Composer metadatauploader endpoint is reachable. It was actively exploited to " +
                        "upload arbitrary files (including JSP web shells), leading to unauthenticated remote code execution.",
                "Apply SAP Security Note 3594142. If Visual Composer is not required, disable the VCFRAMEWORK " +
                        "component and block this endpoint at the Web Dispatcher."));
        e.add(cve("/CTCWebService/CTCWebServiceBean?wsdl", "CTC WebService WSDL (RECON)",
                HIGH, "CVE-2020-6287",
                "The LM Configuration Wizard CTCWebService WSDL is the attack surface for CVE-2020-6287 (RECON), " +
                        "which allows creation of administrative users on the NetWeaver Java engine without authentication.",
                "Apply SAP Security Note 2934135 and restrict access to the LM Configuration Wizard."));
        e.add(cve("/CTCWebService/CTCWebServiceBean", "CTC WebService Endpoint (RECON)",
                HIGH, "CVE-2020-6287",
                "The LM Configuration Wizard CTCWebService SOAP endpoint is reachable. This is the service abused by " +
                        "CVE-2020-6287 (RECON).",
                "Apply SAP Security Note 2934135 and restrict access to the LM Configuration Wizard."));
        e.add(cve("/invoker/EJBInvokerServlet", "EJB Invoker Servlet",
                HIGH, "CVE-2010-5326",
                "The J2EE EJB Invoker servlet is exposed. When left unauthenticated it permits invocation of " +
                        "server-side beans and has been abused for remote code execution.",
                "Apply SAP Security Note 1445998 and disable the Invoker servlets on the AS Java."));
        e.add(cve("/invoker/JMXInvokerServlet", "JMX Invoker Servlet",
                HIGH, "CVE-2010-5326",
                "The J2EE JMX Invoker servlet is exposed. When left unauthenticated it permits invocation of " +
                        "server-side management operations.",
                "Apply SAP Security Note 1445998 and disable the Invoker servlets on the AS Java."));
        e.add(cve("/LMXML", "LMXML Service",
                HIGH, "CVE-2020-6308",
                "The LMXML servlet is reachable. It has been associated with unauthenticated server-side request " +
                        "forgery in the Solution Manager / LM stack (CVE-2020-6308).",
                "Apply the relevant SAP Security Note and restrict access to the Solution Manager infrastructure."));

        // ---------------------------------------------------------------
        // ABAP ICF default services
        // ---------------------------------------------------------------
        e.add(icf("/sap/public/info", "Public System Information", MEDIUM,
                "The /sap/public/info service can disclose SAP system metadata (SID, kernel release, database host, " +
                        "instance name) without authentication."));
        e.add(icf("/sap/bc/ping", "ICF Ping Service", LOW,
                "The /sap/bc/ping ICF node is active, confirming a reachable NetWeaver ABAP stack."));
        e.add(icf("/sap/public/ping", "Public Ping Service", LOW,
                "The /sap/public/ping ICF node responds without authentication, confirming a reachable ABAP stack."));
        e.add(icf("/sap/bc/soap/wsdl", "SOAP Runtime WSDL", LOW,
                "The ABAP SOAP runtime WSDL endpoint is reachable and can enumerate exposed web services."));
        e.add(icf("/sap/bc/soap/rfc", "SOAP RFC Gateway", MEDIUM,
                "The SOAP-to-RFC gateway is reachable. When exposed it can allow remote invocation of RFC-enabled " +
                        "function modules."));
        e.add(icf("/sap/bc/srt/wsil", "Web Service Inspection (WSIL)", LOW,
                "The WSIL inspection endpoint is reachable and can enumerate published web services on the host."));
        e.add(icf("/sap/bc/echo", "ICF Echo Service", LOW,
                "The /sap/bc/echo diagnostic service is active and reflects request data."));
        e.add(icf("/sap/bc/error", "ICF Error Service", LOW,
                "The /sap/bc/error diagnostic service is active and can reveal ICF error-handling behaviour."));
        e.add(icf("/sap/bc/FormToRfc", "FormToRfc Service", MEDIUM,
                "The legacy FormToRfc service is reachable. It maps HTTP form data to RFC calls and has historically " +
                        "been associated with information disclosure and RFC abuse."));
        e.add(icf("/sap/bc/webrfc", "WebRFC Service", MEDIUM,
                "The legacy WebRFC service is reachable. It exposes RFC-enabled function modules over HTTP and has " +
                        "historically been associated with information disclosure."));
        e.add(icf("/sap/bc/gui/sap/its/webgui", "SAP GUI for HTML (WebGUI)", MEDIUM,
                "The SAP GUI for HTML (WebGUI) logon service is reachable, providing browser-based access to SAP " +
                        "transactions."));
        e.add(icf("/sap/public/bc/icf/logoff", "ICF Logoff Service", INFORMATION,
                "The public ICF logoff service is reachable, confirming an active ICF runtime."));
        e.add(icf("/sap/public/bc/ur/Login/assets", "Unified Rendering Login Assets", INFORMATION,
                "SAP Unified Rendering login assets are served without authentication, fingerprinting an SAP logon UI."));

        // ---------------------------------------------------------------
        // BSP applications
        // ---------------------------------------------------------------
        e.add(icf("/sap/bc/bsp/sap/system/login.htm", "BSP System Login", LOW,
                "The BSP system login page is reachable, confirming an exposed BSP runtime."));
        e.add(icf("/sap/bc/bsp/sap/it00/default.htm", "BSP IT00 Demo Application", LOW,
                "The BSP IT00 demo application is reachable. Demo content should not be exposed on production systems."));
        e.add(icf("/sap/bc/bsp/sap/neptune/ping", "Neptune / BSP Ping", LOW,
                "A Neptune (BSP) ping endpoint is reachable, indicating a deployed Neptune / BSP application."));

        // ---------------------------------------------------------------
        // Web Dynpro (ABAP)
        // ---------------------------------------------------------------
        e.add(wd("/sap/bc/webdynpro/sap/wdr_test_apb", "Web Dynpro Test Application", LOW,
                "The Web Dynpro ABAP test application wdr_test_apb is reachable. Test applications should not be " +
                        "exposed on production systems."));
        e.add(wd("/sap/bc/webdynpro/sap/configure_application", "Web Dynpro Application Configuration", MEDIUM,
                "The Web Dynpro application configuration tool is reachable and can expose or alter application " +
                        "configuration."));
        e.add(wd("/sap/bc/webdynpro/sap/configure_component", "Web Dynpro Component Configuration", MEDIUM,
                "The Web Dynpro component configuration tool is reachable and can expose or alter component " +
                        "configuration."));
        e.add(wd("/sap/bc/webdynpro/sap/wd_sise_main_app", "Web Dynpro SISE Main App", MEDIUM,
                "The Web Dynpro SISE application is reachable and can expose system administration functionality."));
        e.add(wd("/sap/bc/webdynpro/sap/wd_sise_user_admin", "Web Dynpro SISE User Admin", MEDIUM,
                "The Web Dynpro SISE user administration application is reachable."));
        e.add(wd("/sap/bc/webdynpro/sap/visual_composer", "Visual Composer (Web Dynpro)", MEDIUM,
                "A Web Dynpro Visual Composer endpoint is reachable. Confirm the component version against " +
                        "CVE-2025-31324 and related notes."));
        e.add(wd("/sap/bc/wdvd/", "Web Dynpro Value Help", LOW,
                "A Web Dynpro value-help / dispatcher endpoint is reachable."));

        // ---------------------------------------------------------------
        // Fiori and Gateway OData
        // ---------------------------------------------------------------
        e.add(gw("/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html", "Fiori Launchpad", INFORMATION,
                "The Fiori Launchpad is reachable, confirming an exposed Fiori front-end."));
        e.add(gw("/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/", "Gateway OData Catalog Service", LOW,
                "The Gateway OData catalog service is reachable and can enumerate registered OData services."));
        e.add(gw("/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection", "Gateway OData Service Collection", LOW,
                "The Gateway OData catalog ServiceCollection can enumerate every registered OData service on the host."));
        e.add(gw("/sap/opu/odata/iwfnd/managingservice/", "Gateway OData Managing Service", MEDIUM,
                "The Gateway OData managing service is reachable and can expose service registration and " +
                        "administration functions."));

        // ---------------------------------------------------------------
        // NetWeaver Java management interfaces
        // ---------------------------------------------------------------
        e.add(java("/nwa", "NetWeaver Administrator", MEDIUM,
                "The NetWeaver Administrator (NWA) console is reachable. It provides broad administrative control " +
                        "over the AS Java."));
        e.add(java("/nwa/sysinfo", "NetWeaver Administrator System Info", MEDIUM,
                "The NWA system information page is reachable and can disclose detailed AS Java configuration."));
        e.add(java("/useradmin", "User Management Engine", MEDIUM,
                "The User Management Engine (UME) administration console is reachable."));
        e.add(java("/startPage", "AS Java Start Page", LOW,
                "The AS Java start page is reachable, confirming an exposed Java engine."));
        e.add(java("/console", "AS Java Console", LOW,
                "An AS Java administration console entry point is reachable."));
        e.add(java("/sap/admin/public/default.html", "AS Java Admin Landing Page", LOW,
                "The AS Java administration landing page is reachable."));
        e.add(java("/wsnavigator", "Web Services Navigator", LOW,
                "The Web Services Navigator is reachable and can enumerate and invoke deployed web services."));
        e.add(java("/ejbexplorer", "EJB Explorer", LOW,
                "The EJB Explorer is reachable and can enumerate deployed enterprise beans."));
        e.add(java("/sr_central/", "Services Registry", LOW,
                "The SAP Services Registry is reachable and can enumerate published services."));
        e.add(java("/utl/SLDInstancesDetailedInfo.jsp", "System Landscape Directory Info", MEDIUM,
                "An SLD detailed-info JSP is reachable and can disclose System Landscape Directory contents."));
        e.add(java("/rtmfCommunicator/html/rtmf/RTMFFrame.jsp", "RTMF Communicator", LOW,
                "The Real Time Multimedia Framework (RTMF) communicator is reachable."));
        e.add(java("/sap/wdisp/admin/public/index.html", "Web Dispatcher Admin Console", MEDIUM,
                "The SAP Web Dispatcher administration console is reachable. When exposed and weakly authenticated it " +
                        "allows an attacker to inspect and alter reverse-proxy routing and TLS configuration."));

        // ---------------------------------------------------------------
        // Enterprise Portal
        // ---------------------------------------------------------------
        e.add(portal("/irj/portal", "Enterprise Portal", LOW,
                "The SAP Enterprise Portal logon (irj/portal) is reachable, confirming an exposed portal."));
        e.add(portal(
                "/irj/servlet/prt/portal/prtroot/pcd!3aportal_content!2fanonymous!2fregisternow",
                "Portal Anonymous Self-Registration", MEDIUM,
                "An Enterprise Portal anonymous self-registration entry point is reachable, which may allow " +
                        "unauthenticated account creation."));

        // ---------------------------------------------------------------
        // HANA XS
        // ---------------------------------------------------------------
        e.add(hana("/sap/hana/xs/admin/", "HANA XS Administration", MEDIUM,
                "The HANA XS administration tool is reachable and can expose database and application configuration."));
        e.add(hana("/sap/hana/xs/ide/editor/", "HANA XS Web IDE Editor", MEDIUM,
                "The HANA XS Web IDE editor is reachable and can expose or modify server-side application code."));
        e.add(hana("/sap/hana/xs/ide/catalog/", "HANA XS Web IDE Catalog", MEDIUM,
                "The HANA XS Web IDE catalog tool is reachable and can expose database catalog objects."));
        e.add(hana("/sap/hana/xs/ide/security/", "HANA XS Web IDE Security Tool", MEDIUM,
                "The HANA XS Web IDE security tool is reachable and can expose or modify security configuration."));
        e.add(hana("/sap/hana/xs/formLogin", "HANA XS Form Login", INFORMATION,
                "The HANA XS form-login endpoint is reachable, fingerprinting a HANA XS engine."));

        // ---------------------------------------------------------------
        // BW / BI
        // ---------------------------------------------------------------
        e.add(new SapEndpoint("/sem/wd/sap/com.sap.ip.bi.web.portal.integration",
                "BW/BI Portal Integration", "BW / BI", LOW, null,
                "A BW/BI portal-integration Web Dynpro endpoint is reachable, indicating an exposed BW front-end.",
                REM_PORTAL));

        ENDPOINTS = Collections.unmodifiableList(e);
    }

    // --- category factory helpers ---------------------------------------

    private static SapEndpoint cve(String path, String title, AuditIssueSeverity sev, String cve,
                                   String detail, String remediation) {
        return new SapEndpoint(path, title, "CVE-tied endpoint", sev, cve, detail, remediation);
    }

    private static SapEndpoint icf(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "ABAP ICF service", sev, null, detail, REM_ICF);
    }

    private static SapEndpoint wd(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "Web Dynpro (ABAP)", sev, null, detail, REM_ICF);
    }

    private static SapEndpoint gw(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "Fiori / Gateway OData", sev, null, detail, REM_GATEWAY);
    }

    private static SapEndpoint java(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "NetWeaver Java management", sev, null, detail, REM_JAVA);
    }

    private static SapEndpoint portal(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "Enterprise Portal", sev, null, detail, REM_PORTAL);
    }

    private static SapEndpoint hana(String path, String title, AuditIssueSeverity sev, String detail) {
        return new SapEndpoint(path, title, "HANA XS", sev, null, detail, REM_HANA);
    }
}
