package wasap.modules;

import burp.*;
import java.util.List;
import wasap.WaSAPPanel;

public class TechDetector {

    private IExtensionHelpers helpers;
    private WaSAPPanel panel;

    public TechDetector(IExtensionHelpers helpers, WaSAPPanel panel) {
        this.helpers = helpers;
        this.panel = panel;
    }

    public void scan(IHttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse == null || baseRequestResponse.getResponse() == null)
            return;

        IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
        List<String> headers = responseInfo.getHeaders();
        String fullResponse = new String(baseRequestResponse.getResponse());

        if (fullResponse.contains("sap.ui.version") || fullResponse.contains("sap-ui-core.js")) {
            String version = "Unknown";
            if (fullResponse.contains("sap.ui.version=")) {
                try {
                    int start = fullResponse.indexOf("sap.ui.version=") + 15;
                    int end = fullResponse.indexOf("\"", start);
                    if (end == -1)
                        end = fullResponse.indexOf("'", start);
                    if (end != -1 && end - start < 10) {
                        version = fullResponse.substring(start, end);
                    }
                } catch (Exception e) {
                }
            }
            panel.addResult(helpers.analyzeRequest(baseRequestResponse).getUrl().toString(),
                    responseInfo.getStatusCode(),
                    0,
                    "Technology",
                    "SAP UI5 Detected (Version: " + version + ")");
        }

        for (String header : headers) {
            String lowerHeader = header.toLowerCase();
            if (lowerHeader.startsWith("server:")) {
                String serverValue = header.substring(7).trim();
                if (serverValue.contains("SAP NetWeaver Application Server")) {
                    String versionInfo = serverValue;
                    String notes = "Server: " + versionInfo;

                    if (versionInfo.contains("7.5") || versionInfo.contains("7.4") || versionInfo.contains("7.3")
                            || versionInfo.contains("7.2")) {
                        notes += " - Check for ICMAD (CVE-2022-22536)";
                    }

                    panel.addResult(helpers.analyzeRequest(baseRequestResponse).getUrl().toString(),
                            responseInfo.getStatusCode(),
                            0,
                            "Server Info",
                            notes);
                }
            }

            if (lowerHeader.startsWith("x-sap-page-generation")) {
                panel.addResult(helpers.analyzeRequest(baseRequestResponse).getUrl().toString(),
                        responseInfo.getStatusCode(),
                        0,
                        "Tech Header",
                        "X-SAP-Page-Generation Detected (SAP specific)");
            }
        }
    }
}
