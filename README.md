# WaSAP - Web Application SAP Scanner

Burp Suite extension that adds SAP-specific scan checks to Burp Scanner. Built
on the Montoya API, WaSAP registers passive and active checks that detect
default SAP endpoints, management interfaces, known SAP CVEs, and SAP-specific
misconfigurations. Findings are raised as standard Burp audit issues and appear
in the Dashboard alongside Burp's own checks.

---

## Features

### CVE-tied checks
Active content-verifying probes:
- **CVE-2025-31324** - NetWeaver Visual Composer Metadata Uploader (unauth RCE;
  the finding also flags the chained deserialization flaw CVE-2025-42999)
- **CVE-2022-22536** - ICMAD (ICM / Web Dispatcher HTTP smuggling, version-based)
- **CVE-2020-6287** - RECON (LM Configuration Wizard, CTCWebService)
- **CVE-2020-6207** - Solution Manager EEM missing authentication (WSDL-verified)
- **CVE-2017-12637** - AS Java Scheduler directory traversal (confirmed by
  retrieving `WEB-INF/web.xml`)

CVE-tagged catalog endpoints (reachability fingerprint, confirm the component
version before acting):
- **CVE-2020-6308** - LMXML
- **CVE-2010-5326** - EJB / JMX Invoker Servlets

### Endpoint catalog (50+ entries)
- **ABAP ICF** - ping, public/info, soap/wsdl, soap/rfc, echo, error, srt/wsil,
  FormToRfc, webrfc, WebGUI
- **BSP applications** - IT00 demo, Neptune, system login
- **Web Dynpro (ABAP)** - configure_application, configure_component,
  wdr_test_apb, wd_sise_main_app, wd_sise_user_admin, visual_composer, wdvd
- **Fiori & Gateway OData** - Fiori Launchpad, catalog service, managing service,
  start_up, Page Builder, Launchpad customizing (apb_lpd_cust)
- **NetWeaver Java management** - NWA, useradmin, wsnavigator, ejbexplorer,
  sr_central, SLD, RTMF, Web Dispatcher admin console
- **Enterprise Portal** - irj/portal, anonymous registration entry point
- **HANA XS** - admin, IDE editor / catalog / security, formLogin
- **BW / BI** - portal integration

### Passive SAP-specific issues
- SAP UI5 framework fingerprint (with version extraction)
- SAP NetWeaver `Server` header disclosure
- SAP proprietary response headers (`x-sap-page-generation`, `sap-server`,
  `sap-perf-fesrec`, `x-sap-login-page`, `sap-usercontext`)
- SAP session cookie flag checks (`MYSAPSSO2`, `SAP_SESSIONID_*`, `PortalAlias`,
  `saplb_*`, `sap-usercontext`, `sap-login-XSRF`) - only SAP cookies, not generic
- ABAP / J2EE verbose error disclosure

### Per-insertion-point active checks
SAP-specific parameter checks on `sap-client`, `sap-language`, `sap-user`,
`sap-syscmd`, `sap-sessioncmd`, `sap-contextid`, `sap-locale`,
`sap-login-locale`, `sap-accessibility`, `sap-ssc`. Designed not to duplicate
Burp Scanner's built-in XSS / SQLi / traversal fuzzing - it runs only on SAP
parameter names and targets SAP error disclosure.

---

## Design

WaSAP registers three scan checks with Burp Scanner:

- **`SapPassiveScanCheck`** (`PassiveScanCheck`, `PER_REQUEST`) - runs on every
  audited response. Detects SAP fingerprints, NetWeaver server header
  disclosure, SAP-specific response headers, SAP session cookies without
  `HttpOnly` / `Secure` flags, and ABAP/J2EE verbose error pages.
- **`SapHostScanCheck`** (`ActiveScanCheck`, `PER_HOST`) - Burp runs it exactly
  once per host, regardless of how many insertion points the host exposes.
  Enumerates the endpoint catalog and runs deeper CVE-specific probes. A random
  baseline probe is issued first so that custom 404 / SPA catch-all responses
  can be filtered out.
- **`SapInsertionPointScanCheck`** (`ActiveScanCheck`, `PER_INSERTION_POINT`) -
  runs on every insertion point but only acts on SAP-specific parameter names.
  Active checks issue their requests through the scan-task `Http` object so Burp
  links, scopes and throttles them with the audit.

All findings are raised via `AuditIssue.auditIssue(...)` with severity,
confidence, background, remediation background, and the request/response that
produced them.

**False-positive controls.** Host active findings require SAP corroboration
before they are raised: either the host fingerprints as SAP (SAP product in the
`Server` header, an SAP-specific response header, or an SAP session cookie - on
the base response, the root page, or a content-verified `/sap/public/info`), or
the specific endpoint response itself carries SAP markers. A reachable but
generic path, or a bare `HTTP 500` on an unrelated application, does not raise an
`SAP:` issue. CVE probes grade confidence by evidence strength (for example, the
Visual Composer check reports `FIRM` on `200`/`405` from an SAP host and
`TENTATIVE` on an ambiguous `500`), and the CTC, RECON/EEM WSDL, HYPARCHIV XSS
and `/sap/public/info` checks verify response content rather than status alone.

---

## Installation

1. Download `WaSAP.jar` from the [releases page](https://github.com/zeroscience/WaSAP/releases)
   or build it from source (see below).
2. Open **Burp Suite** -> **Extensions** -> **Installed** -> **Add**.
3. Extension type: **Java**, select `WaSAP.jar`.
4. Check the **Output** tab - you should see:

   ```
   [WaSAP] Loaded SAP security scan checks.
   [WaSAP] Passive (per request) : SAP tech fingerprint, cookie flags, error disclosure.
   [WaSAP] Active (per host) : SAP default endpoints, management interfaces, CVE-tied paths.
   [WaSAP] Active (per insertion point) : SAP-specific parameter checks.
   ```

Burp bundles the Montoya API, so no additional dependencies are required.

---

## Usage

WaSAP does not add a tab or context menu - it registers scan checks directly
with Burp Scanner. Run scans as you normally would and SAP findings appear
alongside Burp's own issues.

**To test:** right-click a request -> **Scan** -> **Audit** (active scan
triggers the per-host endpoint enumeration + CVE checks + per-insertion-point
SAP param checks; passive scans trigger fingerprint / cookie / error-disclosure
issues). Findings appear in **Dashboard -> Issues** and
**Target -> Site map -> Issues**, prefixed with `SAP:`.

Typical workflow:
1. Browse the target SAP application through the Burp proxy.
2. In **Target -> Site map**, right-click the SAP host -> **Scan** -> **Audit
   selected items**.
3. Watch the **Dashboard** for new `SAP: ...` findings as the host is enumerated
   and insertion points are probed.
4. Passive checks also fire automatically as new responses flow through the
   proxy if passive scanning is enabled.

---

## Build from Source

Requirements: JDK 17+ (the bundled Gradle wrapper handles Gradle).

```bash
git clone https://github.com/zeroscience/wasap.git
cd wasap
./gradlew jar
# -> build/libs/WaSAP-2.5.1.jar
```

The build declares Montoya API as `compileOnly` (Burp already bundles it, so
it must not be packaged into the extension jar).

### Manual build (no Gradle)

```bash
# 1. Fetch the Montoya API jar from Maven Central
curl -sSLo montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar

# 2. Compile
mkdir -p build/classes
javac -cp montoya-api.jar -d build/classes $(find src/main/java -name "*.java")

# 3. Package (the resources dir carries the Montoya service manifest that
#    tells Burp which class to load - the jar will not load without it)
jar cf WaSAP.jar -C build/classes . -C src/main/resources .
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history. The current
release is **2.5.1**.

---

## Project Layout

```
src/main/java/wasap/
|-- WaSAPExtension.java                   # BurpExtension entry point, registers the 3 checks
`-- checks/
    |-- SapPassiveScanCheck.java          # PassiveScanCheck  (PER_REQUEST)
    |-- SapHostScanCheck.java             # ActiveScanCheck   (PER_HOST)
    |-- SapInsertionPointScanCheck.java   # ActiveScanCheck   (PER_INSERTION_POINT)
    |-- SapIssueConsolidation.java        # Shared issue de-duplication
    |-- SapEndpoint.java                  # Catalog entry model
    |-- SapEndpointCatalog.java           # 50+ SAP endpoints with severity / CVE metadata
    |-- SapHostChecks.java                # Per-host probe loop + baseline 404 detection
    |-- SapActiveChecks.java              # CVE-specific active probes
    |-- SapPassiveChecks.java             # Passive fingerprint / cookie / error checks
    `-- SapInsertionPointChecks.java      # Per-insertion-point SAP parameter checks

src/main/resources/
`-- META-INF/services/burp.api.montoya.BurpExtension   # Montoya service manifest
```

---

## Disclaimer

This tool is for educational and authorised security testing purposes only.
The author is not responsible for any misuse or damage caused by this tool.

---

**Version:** 2.5.1
**Author:** Gjoko Krstic
