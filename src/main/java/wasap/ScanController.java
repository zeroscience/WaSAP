package wasap;

import burp.*;
import wasap.modules.*;

public class ScanController {

    private IBurpExtenderCallbacks callbacks;
    private WaSAPPanel panel;
    private EndpointScanner endpointScanner;
    private TechDetector techDetector;
    private VulnScanner vulnScanner;
    private Fuzzer fuzzer;

    public ScanController(IBurpExtenderCallbacks callbacks, WaSAPPanel panel) {
        this.callbacks = callbacks;
        this.panel = panel;
        this.endpointScanner = new EndpointScanner(callbacks, panel);
        this.techDetector = new TechDetector(callbacks.getHelpers(), panel);
        this.vulnScanner = new VulnScanner(callbacks, panel);
        this.fuzzer = new Fuzzer(callbacks, panel);
    }

    public void startScan(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null)
            return;

        new Thread(() -> {
            for (IHttpRequestResponse message : messages) {
                IHttpService httpService = message.getHttpService();

                endpointScanner.scan(httpService);

                vulnScanner.activeScan(httpService);

                techDetector.scan(message);
                vulnScanner.scan(message);

                fuzzer.fuzz(message);
            }
        }).start();
    }
}
