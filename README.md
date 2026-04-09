# WaSAP — Web Application SAP Scanner

Burp Suite extension that adds SAP-specific scan checks to Burp Scanner. Built
on the Montoya API, WaSAP registers passive and active checks that detect
default SAP endpoints, management interfaces, known SAP CVEs, and SAP-specific
misconfigurations. Findings are raised as standard Burp audit issues and appear
in the Dashboard alongside Burp's own checks.

---

## Features

### CVE-tied checks
- **CVE-2025-31324** — NetWeaver Visual Composer Metadata Uploader (unauth RCE)
- **CVE-2022-22536** — ICMAD (ICM / Web Dispatcher HTTP smuggling, version-based)
- **CVE-2020-6287** — RECON (LM Configuration Wizard, CTCWebService)
- **CVE-2020-6308** — LMXML
- **CVE-2021-33690** — FormToRfc
- **CVE-2011-1516** — WebRFC
- **CVE-2010-5326** — EJB / JMX Invoker Servlets

### Endpoint catalog (70+ entries)
- **ABAP ICF** — ping, public/info, soap/wsdl, soap/rfc, echo, error, srt/wsil,
  FormToRfc, webrfc, ...
- **BSP applications** — IT00 demo, Neptune, system login
- **Web Dynpro (ABAP)** — admin, configure_application, configure_component,
  wdr_test_apb, wd_sise_main_app, wd_sise_user_admin, visual_composer, wdvd
- **Fiori & Gateway OData** — Fiori Launchpad, catalog service, managing service
- **NetWeaver Java management** — NWA, useradmin, wsnavigator, ejbexplorer,
  sr_central, SLD, ITSAM/Solution Manager, RTMF
- **Enterprise Portal** — irj/portal, anonymous registration entry point
- **HANA XS** — admin, IDE editor / catalog / security, lifecycle management,
  Web IDE, formLogin
- **BW / BI** — portal integration

### Passive SAP-specific issues
- SAP UI5 framework fingerprint (with version extraction)
- SAP NetWeaver `Server` header disclosure
- SAP proprietary response headers (`x-sap-page-generation`, `sap-server`,
  `sap-perf-fesrec`, `x-sap-login-page`, `sap-usercontext`)
- SAP session cookie flag checks (`MYSAPSSO2`, `SAP_SESSIONID_*`, `PortalAlias`,
  `saplb_*`, `sap-login-XSRF`) — only SAP cookies, not generic
- ABAP / J2EE verbose error disclosure

### Per-insertion-point active checks
SAP-specific parameter checks on `sap-client`, `sap-language`, `sap-user`,
`sap-syscmd`, `sap-sessioncmd`, `sap-contextid`, `sap-locale`,
`sap-login-locale`, `sap-accessibility`, `sap-ssc`. Designed not to duplicate
Burp Scanner's built-in XSS / SQLi / traversal fuzzing — it runs only on SAP
parameter names and targets SAP error disclosure.

---

## Design

WaSAP implements a single `ScanCheck` with three layers of logic:

- **Passive checks** — run on every audited response. Detect SAP fingerprints,
  NetWeaver server header disclosure, SAP-specific response headers, SAP
  session cookies without `HttpOnly` / `Secure` flags, and ABAP/J2EE verbose
  error pages.
- **Per-host active checks** — run exactly once per host (tracked via a
  `ConcurrentHashMap`, regardless of how many insertion points the host
  exposes). Enumerates the endpoint catalog and runs deeper CVE-specific
  probes. A random baseline probe is issued first so that custom 404 / SPA
  catch-all responses can be filtered out.
- **Per-insertion-point active checks** — run on every insertion point but
  only act on SAP-specific parameter names.

All findings are raised via `AuditIssue.auditIssue(...)` with severity,
confidence, background, remediation background, and the request/response that
produced them.

---

## Installation

1. Download `WaSAP.jar` from the [releases page](https://github.com/portswigger/wasap/releases)
   or build it from source (see below).
2. Open **Burp Suite** → **Extensions** → **Installed** → **Add**.
3. Extension type: **Java**, select `WaSAP.jar`.
4. Check the **Output** tab — you should see:

   ```
   [WaSAP] Loaded SAP security scan checks.
   [WaSAP] Passive : SAP tech fingerprint, cookie flags, error disclosure.
   [WaSAP] Active (per host) : SAP default endpoints, management interfaces, CVE-tied paths.
   [WaSAP] Active (per insertion point) : SAP-specific parameter checks.
   ```

Burp bundles the Montoya API, so no additional dependencies are required.

---

## Usage

WaSAP does not add a tab or context menu — it registers scan checks directly
with Burp Scanner. Run scans as you normally would and SAP findings appear
alongside Burp's own issues.

**To test:** right-click a request → **Scan** → **Audit** (active scan
triggers the per-host endpoint enumeration + CVE checks + per-insertion-point
SAP param checks; passive scans trigger fingerprint / cookie / error-disclosure
issues). Findings appear in **Dashboard → Issues** and
**Target → Site map → Issues**, prefixed with `SAP:`.

Typical workflow:
1. Browse the target SAP application through the Burp proxy.
2. In **Target → Site map**, right-click the SAP host → **Scan** → **Audit
   selected items**.
3. Watch the **Dashboard** for new `SAP: …` findings as the host is enumerated
   and insertion points are probed.
4. Passive checks also fire automatically as new responses flow through the
   proxy if passive scanning is enabled.

---

## Build from Source

Requirements: JDK 17+, Gradle (or use the wrapper if present).

```bash
git clone https://github.com/zeroscience/wasap.git
cd wasap
./gradlew jar
# -> build/libs/WaSAP-2.0.0.jar
```

The build declares Montoya API as `compileOnly` (Burp already bundles it, so
it must not be packaged into the extension jar).

### Manual build (no Gradle)

```bash
# 1. Fetch the Montoya API jar from Maven Central
curl -sSLo montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar

# 2. Compile
mkdir -p build/classes
javac -cp montoya-api.jar -d build/classes $(find src/main/java -name "*.java")

# 3. Package
jar cf WaSAP.jar -C build/classes .
```

---

## Changelog

### 2.5.1 — Montoya rewrite
- **Full migration from the legacy Extender API to the Montoya API.** The
  extension now registers a proper `ScanCheck` with Burp Scanner instead of
  running ad-hoc probes from a context-menu action.
- **Findings raised as `AuditIssue`** with severity, confidence, background,
  remediation background and evidence request/response. Issues appear in the
  Burp Dashboard and Site map alongside Burp's own checks.
- **Per-host vs per-insertion-point scheduling.** The endpoint catalog is
  probed exactly once per host (tracked via `ConcurrentHashMap`); parameter
  checks run per insertion point but only on SAP-specific parameter names.
- **Removed the legacy generic Fuzzer** (XSS / SQLi / traversal payloads) that
  duplicated Burp Scanner's built-in checks.
- **Removed the custom UI panel, context menu, ScanController, and CSV
  export.** Output is delivered through Burp Scanner.
- **Data-driven endpoint catalog** (`SapEndpointCatalog`, 70+ entries) covering
  ABAP ICF, BSP, Web Dynpro admin apps, Fiori/Gateway OData, NetWeaver Java
  management interfaces, Enterprise Portal, HANA XS, BW/BI, and CVE-tied paths.
- **New CVE checks:** Visual Composer Metadata Uploader (CVE-2025-31324),
  ICMAD version detection (CVE-2022-22536), RECON WSDL content verification
  (CVE-2020-6287), `/sap/public/info` unauthenticated system-info disclosure,
  LMXML (CVE-2020-6308), FormToRfc (CVE-2021-33690), WebRFC (CVE-2011-1516),
  Invoker servlets (CVE-2010-5326).
- **Baseline-aware probing.** A random `/wasap-probe-<nonce>` request is
  issued first to learn a host's custom 404 / catch-all behaviour; probes
  whose status and length match the baseline are suppressed to reduce false
  positives on SPA hosts.
- **SAP-scoped passive checks.** Cookie security flag checks now only fire on
  SAP cookies (`MYSAPSSO2`, `SAP_SESSIONID_*`, `PortalAlias`, `saplb_*`,
  `sap-login-XSRF`) rather than every cookie; fingerprint checks only fire on
  SAP-specific headers.
- **Reflected XSS probe uses a random marker** instead of a static
  `<script>alert(1)</script>` payload, improving reliability and reducing
  collisions with pages that happen to contain the static string.
- **Build system:** switched to Java 17, `compileOnly` Montoya dependency.

### 1.x — legacy (pre-Montoya)
- Context-menu driven enumeration of ~50 SAP endpoints.
- Generic XSS / SQLi / traversal fuzzer.
- Custom Swing UI panel with CSV export.
- Built on the legacy `burp-extender-api` 2.3.

---

## Project Layout

```
src/main/java/wasap/
├── WaSAPExtension.java                   # BurpExtension entry point
└── checks/
    ├── SapScanCheck.java                 # Unified ScanCheck (per-host tracking + dispatch)
    ├── SapEndpoint.java                  # Catalog entry model
    ├── SapEndpointCatalog.java           # 70+ SAP endpoints with severity / CVE metadata
    ├── SapHostChecks.java                # Per-host probe loop + baseline 404 detection
    ├── SapActiveChecks.java              # CVE-specific active probes
    ├── SapPassiveChecks.java             # Passive fingerprint / cookie / error checks
    └── SapInsertionPointChecks.java      # Per-insertion-point SAP parameter checks
```

---

## Disclaimer

This tool is for educational and authorised security testing purposes only.
The author is not responsible for any misuse or damage caused by this tool.

---

**Version:** 2.5.1
**Author:** Gjoko Krstic
