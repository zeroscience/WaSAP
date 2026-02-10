package wasap.modules;

import burp.*;
import java.net.URL;
import java.util.List;
import wasap.WaSAPPanel;

public class Fuzzer {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private WaSAPPanel panel;

    private static final String[] PAYLOADS = {
            "' OR '1'='1",
            "\"><script>alert(1)</script>",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../windows/win.ini"
    };

    public Fuzzer(IBurpExtenderCallbacks callbacks, WaSAPPanel panel) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.panel = panel;
    }

    public void fuzz(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = requestInfo.getParameters();

        if (parameters.isEmpty())
            return;

        for (IParameter param : parameters) {
            if (param.getType() == IParameter.PARAM_COOKIE)
                continue;

            for (String payload : PAYLOADS) {
                IParameter newParam = helpers.buildParameter(param.getName(), payload, param.getType());
                byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);

                IHttpService httpService = baseRequestResponse.getHttpService();
                try {
                    IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, newRequest);
                    if (response != null && response.getResponse() != null) {
                        analyzeFuzzResponse(response, payload);
                    }
                } catch (Exception e) {
                }
            }
        }
    }

    private void analyzeFuzzResponse(IHttpRequestResponse response, String payload) {
        String body = new String(response.getResponse());
        IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());

        if (payload.contains("script") && body.contains(payload)) {
            panel.addResult(helpers.analyzeRequest(response).getUrl().toString(),
                    responseInfo.getStatusCode(),
                    0,
                    "Fuzzing",
                    "Possible Reflected XSS: " + payload);
        }

        if (payload.contains("'") && (body.contains("SQL syntax") || body.contains("ORA-") || body.contains("MySQL"))) {
            panel.addResult(helpers.analyzeRequest(response).getUrl().toString(),
                    responseInfo.getStatusCode(),
                    0,
                    "Fuzzing",
                    "Possible SQLi Error: " + payload);
        }
    }
}
