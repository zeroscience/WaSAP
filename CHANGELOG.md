# Changelog

All notable changes to WaSAP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.2] - 2026-09-28

### Added
- `SapEndpointCatalog` with 50+ curated SAP endpoints grouped by category
  (ABAP ICF, BSP, Web Dynpro, Fiori/Gateway OData, NetWeaver Java management,
  Enterprise Portal, HANA XS, BW/BI, CVE-tied). `SapHostChecks` referenced this
  class but it was never committed, so the project did not compile.
- Montoya extension service manifest
  (`META-INF/services/burp.api.montoya.BurpExtension`) so Burp can load the
  extension.
- `/sap/public/info` disclosure now parses the `RFC_SYSTEM_INFO` response and
  reports the exact fields disclosed (SID, database system and host, kernel
  release, OS, application host, IP).
- SAP Web Dispatcher admin console detection.
- Gradle wrapper (8.10.2, with `distributionSha256Sum` verification),
  `.gitignore` and `.gitattributes`.

### Changed
- Split the single combined `ScanCheck` into three purpose-built checks on the
  current Montoya scan-check API (montoya-api 2026.7):
  - `SapPassiveScanCheck` - `PassiveScanCheck`, registered `PER_REQUEST`.
  - `SapHostScanCheck` - `ActiveScanCheck`, registered `PER_HOST`, so the
    endpoint catalog and CVE probes run exactly once per host (Burp handles the
    scheduling; the manual host-tracking set is gone).
  - `SapInsertionPointScanCheck` - `ActiveScanCheck`, registered
    `PER_INSERTION_POINT`.
- Active checks now issue their requests through the scan-task `Http` object so
  Burp links, scopes and throttles them with the audit.

### Removed
- The deprecated `registerScanCheck(ScanCheck)` registration path.
- Leftover legacy Extender API code (`BurpExtender`, `ScanController`,
  `WaSAPPanel`, `modules/*`) and the bundled `burp-extender-api` JAR. The 2.5.1
  notes stated these were removed, but the files were still present and pulled
  in the legacy API. The build now declares Montoya only.

## [2.5.1] - Montoya rewrite

### Changed
- Full migration from the legacy Extender API to the Montoya API. Findings are
  raised as `AuditIssue` objects (severity, confidence, background, remediation
  background, evidence) and appear in the Burp Dashboard and Site map alongside
  Burp's own checks.
- Endpoint catalog probed once per host; parameter checks run per insertion
  point but only on SAP-specific parameter names.
- Baseline-aware probing: a random `/wasap-probe-<nonce>` request learns a
  host's custom 404 / catch-all behaviour, and probes whose status and length
  match the baseline are suppressed to reduce false positives.
- SAP-scoped passive checks: cookie security-flag checks only fire on SAP
  cookies (`MYSAPSSO2`, `SAP_SESSIONID_*`, `PortalAlias`, `saplb_*`,
  `sap-login-XSRF`); fingerprint checks only fire on SAP-specific headers.
- Reflected XSS probe uses a random marker instead of a static payload.
- Build switched to Java 17 with a `compileOnly` Montoya dependency.

### Added
- Active CVE checks: Visual Composer Metadata Uploader (CVE-2025-31324), ICMAD
  version detection (CVE-2022-22536), RECON WSDL content verification
  (CVE-2020-6287), and `/sap/public/info` unauthenticated system-info
  disclosure. The catalog additionally tags LMXML (CVE-2020-6308) and the
  EJB / JMX Invoker servlets (CVE-2010-5326).

### Removed
- The legacy generic fuzzer (XSS / SQLi / traversal) that duplicated Burp
  Scanner's built-in checks, and the custom UI panel, context menu,
  `ScanController` and CSV export.

## [1.x] - legacy (pre-Montoya)

- Context-menu driven enumeration of ~50 SAP endpoints.
- Generic XSS / SQLi / traversal fuzzer.
- Custom Swing UI panel with CSV export.
- Built on the legacy `burp-extender-api` 2.3.

[2.5.2]: https://github.com/zeroscience/WaSAP/releases/tag/2.5.2
[2.5.1]: https://github.com/zeroscience/WaSAP/releases/tag/2.5.1
