package wasap;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import wasap.checks.SapHostScanCheck;
import wasap.checks.SapInsertionPointScanCheck;
import wasap.checks.SapPassiveScanCheck;

public class WaSAPExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("WaSAP - SAP Security Scanner");

        // Passive: SAP fingerprints, cookie flags and error disclosure, once per request.
        api.scanner().registerPassiveScanCheck(new SapPassiveScanCheck(api), ScanCheckType.PER_REQUEST);

        // Active (per host): endpoint-catalog enumeration and CVE-tied probes, once per host.
        api.scanner().registerActiveScanCheck(new SapHostScanCheck(api), ScanCheckType.PER_HOST);

        // Active (per insertion point): SAP-specific parameter checks only.
        api.scanner().registerActiveScanCheck(new SapInsertionPointScanCheck(api), ScanCheckType.PER_INSERTION_POINT);

        api.logging().logToOutput("[WaSAP] Loaded SAP security scan checks.");
        api.logging().logToOutput("[WaSAP] Passive (per request) : SAP tech fingerprint, cookie flags, error disclosure.");
        api.logging().logToOutput("[WaSAP] Active (per host) : SAP default endpoints, management interfaces, CVE-tied paths.");
        api.logging().logToOutput("[WaSAP] Active (per insertion point) : SAP-specific parameter checks.");
    }
}
