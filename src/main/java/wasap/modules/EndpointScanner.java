package wasap.modules;

import burp.*;
import java.net.URL;
import wasap.WaSAPPanel;

public class EndpointScanner {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private WaSAPPanel panel;

    private static final String[] SAP_ENDPOINTS = {
            "/sap/bc/ping",
            "/sap/public/info",
            "/sap/public/ping",
            "/sap/bc/soap/wsdl",
            "/sap/bc/webdynpro/sap/admin",
            "/nwa",
            "/nwa/sysinfo",
            "/useradmin",
            "/startPage",
            "/console",
            "/sap/admin/public/default.html",
            "/irj/portal",
            "/sap/bc/gui/sap/its/webgui",
            "/sap/bc/bsp/sap/system/login.htm",
            "/sap/bc/bsp/sap/it00/default.htm",
            "/sap/bc/webdynpro/sap/configure_application",
            "/sap/bc/webdynpro/sap/configure_component",
            "/sem/wd/sap/com.sap.ip.bi.web.portal.integration",
            "/sap/hana/xs/admin/",
            "/sap/hana/xs/ide/editor/",
            "/sap/hana/xs/ide/catalog/",
            "/sap/hana/xs/ide/security/",
            "/sap/hana/xs/formLogin",
            "/sap/bc/wdvd/",
            "/sap/bc/echo",
            "/sap/bc/error",
            "/index.html",
            "/sap/bc/webdynpro/sap/wd_sise_main_app",
            "/sap/bc/webdynpro/sap/wd_sise_user_admin",
            "/webdynpro/resources/local/forgotpassword/ForgotPassword",
            "/sap/public/bc/icf/logoff",
            "/sap/public/bc/ur/Login/assets",
            "/sap/bc/webdynpro/sap/wdr_test_apb",
            "/wsnavigator",
            "/webdynpro/welcome/Welcome.html",
            "/webdynpro/dispatcher/sap.com/tc~wd~tools/Explorer",
            "/webdynpro/dispatcher/sap.com/tc~wd~tools/WebDynproConsole",
            "/sr_central/",
            "/webdynpro/dispatcher/sap.com/tc~esi~esp~er~ui/Menu",
            "/utl/SLDInstancesDetailedInfo.jsp",
            "/ejbexplorer",
            "/webdynpro/resources/sap.com/tc~lm~itsam~ui~mainframe~wd/FloorPlanApp?applicationViewID=ExplorerView&applicationID=com.sap.itsam.ejb.explorer&isLocal=true",
            "/webdynpro/resources/sap.com/tc~lm~itsam~ui~lv~client_ui/LVApp?conn=filter[Log_ID:C0000A12141B03100000000000221C7E]view[Default Trace (Java)]",
            "/rtmfCommunicator/html/rtmf/RTMFFrame.jsp",
            "/irj/servlet/prt/portal/prtroot/pcd!3aportal_content!2fanonymous!2fregisternow",
            "/CTCWebService/CTCWebServiceBean",
            "/CTCWebService/CTCWebServiceBean?wsdl",
            "/invoker/EJBInvokerServlet",
            "/invoker/J2EEInvokerServlet",
            "/LMXML",
            "/sap/bc/bsp/sap/neptune/ping",
            "/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html",
            "/sap/bc/webdynpro/sap/visual_composer",
            "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/",
            "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection",
            "/sap/opu/odata/iwfnd/managingservice/"
    };

    public EndpointScanner(IBurpExtenderCallbacks callbacks, WaSAPPanel panel) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.panel = panel;
    }

    public void scan(IHttpService httpService) {
        for (String endpoint : SAP_ENDPOINTS) {
            checkSapEndpoint(httpService, endpoint);
        }
    }

    private void checkSapEndpoint(IHttpService httpService, String endpoint) {
        try {
            URL url = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), endpoint);
            byte[] request = helpers.buildHttpRequest(url);
            IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);

            if (response != null && response.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
                int statusCode = responseInfo.getStatusCode();
                int length = response.getResponse().length - responseInfo.getBodyOffset();
                String mime = responseInfo.getStatedMimeType();

                String fullUrl = url.toString();

                String notes = "";
                if (statusCode == 200)
                    notes = "Accessible";
                else if (statusCode == 401 || statusCode == 403)
                    notes = "Auth Required";
                else if (statusCode == 404)
                    notes = "Not Found";
                else if (statusCode == 500)
                    notes = "Server Error";
                else if (statusCode >= 300 && statusCode < 400)
                    notes = "Redirect";
                else if (statusCode == 405)
                    notes = "Method Not Allowed";

                if (statusCode == 200) {
                    if (endpoint.equals("/nwa") || endpoint.equals("/irj/portal") || endpoint.equals("/useradmin")
                            || endpoint.equals("/console")) {
                        notes += " - Tip: Try SAP*/06071992, DDIC/19920706, EARLYWATCH/SUPPORT";
                    }
                }
                if (endpoint.startsWith("/CTCWebService") && (statusCode == 200 || statusCode == 405)) {
                    notes += " - POTENTIAL RECON (CVE-2020-6287)";
                }
                if (endpoint.startsWith("/invoker") && (statusCode == 200 || statusCode == 500)) {
                    notes += " - POTENTIAL INVOKER (CVE-2010-5326)";
                }
                if (endpoint.contains("visual_composer") && statusCode == 200) {
                    notes += " - CHECK CVE-2025-31324";
                }
                if (endpoint.contains("odata") && statusCode == 200) {
                    notes += " - OData Service Exposed";
                }

                panel.addResult(fullUrl, statusCode, length, mime, notes);

                if (statusCode != 404) {
                    callbacks.addToSiteMap(response);
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error scanning " + endpoint + ": " + e.getMessage());
        }
    }
}
