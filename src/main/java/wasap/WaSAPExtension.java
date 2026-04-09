package wasap;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import wasap.checks.SapScanCheck;

public class WaSAPExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("WaSAP - SAP Security Scanner");
        api.scanner().registerScanCheck(new SapScanCheck(api));

        api.logging().logToOutput("[WaSAP] Loaded SAP security scan checks.");
        api.logging().logToOutput("[WaSAP] Passive : SAP tech fingerprint, cookie flags, error disclosure.");
        api.logging().logToOutput("[WaSAP] Active (per host) : SAP default endpoints, management interfaces, CVE-tied paths.");
        api.logging().logToOutput("[WaSAP] Active (per insertion point) : SAP-specific parameter checks.");
    }
}
