package wasap.modules;

import burp.*;
import java.util.List;
import java.net.URL;
import wasap.WaSAPPanel;

public class VulnScanner {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private WaSAPPanel panel;

    public VulnScanner(IBurpExtenderCallbacks callbacks, WaSAPPanel panel) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.panel = panel;
    }

    public void scan(IHttpRequestResponse baseRequestResponse) {
        IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
        List<ICookie> cookies = responseInfo.getCookies();

        for (ICookie cookie : cookies) {
            String name = cookie.getName();
            if (name.equals("JSESSIONID") || name.equals("MYSAPSSO2") || name.equals("PortalAlias")
                    || name.startsWith("saplb_")) {
                checkCookieFlags(responseInfo, baseRequestResponse, name);
            }
        }

        String body = new String(baseRequestResponse.getResponse());
        if (body.contains("sap-system-login-oninputprocessing")) {
            if (!body.contains("name=\"csrf_token\"") && !body.contains("name=\"sap-csrf-token\"")) {
            }
        }
    }

    public void activeScan(IHttpService httpService) {
        checkHypR3XSS(httpService);
        checkRTMFMisconfig(httpService);
    }

    private void checkHypR3XSS(IHttpService httpService) {
        String rawPath = "/HYPARCHIV/HypR3Http.dll?zsl<script>alert(1)</script>zsl=1";
        try {
            StringBuilder reqBuilder = new StringBuilder();
            reqBuilder.append("GET ").append(rawPath).append(" HTTP/1.1\r\n");
            reqBuilder.append("Host: ").append(httpService.getHost());
            int port = httpService.getPort();
            if (port != 80 && port != 443) {
                reqBuilder.append(":").append(port);
            }
            reqBuilder.append("\r\n");
            reqBuilder.append("Connection: close\r\n");
            reqBuilder.append("\r\n");

            byte[] request = reqBuilder.toString().getBytes();
            IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);

            if (response != null && response.getResponse() != null) {
                byte[] responseBytes = response.getResponse();
                IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                String body = new String(responseBytes);

                int length = responseBytes.length - responseInfo.getBodyOffset();

                if (body.contains("<script>alert(1)</script>")) {
                    String fullUrl = httpService.getProtocol() + "://" + httpService.getHost() + ":" + port + rawPath;
                    panel.addResult(fullUrl,
                            responseInfo.getStatusCode(),
                            length,
                            "Reflected XSS",
                            "Vulnerable to Reflected XSS in HypR3Http.dll");
                    callbacks.addToSiteMap(response);
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error checking HypR3XSS: " + e.getMessage());
        }
    }

    private void checkRTMFMisconfig(IHttpService httpService) {
        String endpoint = "/rtmfCommunicator/rtmfServlet";
        try {
            URL url = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), endpoint);
            byte[] request = helpers.buildHttpRequest(url);
            IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);

            if (response != null && response.getResponse() != null) {
                int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
                if (statusCode == 500) {
                    panel.addResult(url.toString(),
                            statusCode,
                            0,
                            "Misconfiguration",
                            "RTMF Servlet misconfiguration (500 Error)");
                    callbacks.addToSiteMap(response);
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error checking RTMF: " + e.getMessage());
        }
    }

    private void checkCookieFlags(IResponseInfo responseInfo, IHttpRequestResponse baseRequestResponse,
            String cookieName) {
        List<String> headers = responseInfo.getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("set-cookie: " + cookieName.toLowerCase()) ||
                    header.toLowerCase().startsWith("set-cookie: " + cookieName)) {

                String lowerHeader = header.toLowerCase();
                boolean httpOnly = lowerHeader.contains("httponly");
                boolean secure = lowerHeader.contains("secure");

                if (!httpOnly || !secure) {
                    String issue = "Cookie Missing Flags: " + cookieName;
                    String details = "";
                    if (!httpOnly)
                        details += "Missing HttpOnly; ";
                    if (!secure)
                        details += "Missing Secure; ";

                    panel.addResult(helpers.analyzeRequest(baseRequestResponse).getUrl().toString(),
                            responseInfo.getStatusCode(),
                            0,
                            "Security Configuration",
                            issue + " - " + details);
                }
            }
        }
    }
}
