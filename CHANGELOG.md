# Changelog

All notable changes to WaSAP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.5.1] - Montoya scanner

### Added
- `SapEndpointCatalog` with 50+ curated SAP endpoints grouped by category
  (ABAP ICF, BSP, Web Dynpro, Fiori/Gateway OData, NetWeaver Java management,
  Enterprise Portal, HANA XS, BW/BI, CVE-tied).
- Montoya extension service manifest
  (`META-INF/services/burp.api.montoya.BurpExtension`) so Burp can load the
  extension.
- Active CVE checks: Visual Composer Metadata Uploader (CVE-2025-31324), ICMAD
  version detection (CVE-2022-22536), RECON WSDL content verification
  (CVE-2020-6287), and `/sap/public/info` unauthenticated system-info
  disclosure. The catalog additionally tags LMXML (CVE-2020-6308) and the
  EJB / JMX Invoker servlets (CVE-2010-5326).
- `/sap/public/info` disclosure parses the `RFC_SYSTEM_INFO` response and
  reports the exact fields disclosed (SID, database system and host, kernel
  release, OS, application host, IP).
- SAP Web Dispatcher admin console detection.
- Baseline-aware probing: a random `/wasap-probe-<nonce>` request learns a
  host's custom 404 / catch-all behaviour, and probes whose status and length
  match the baseline are suppressed to reduce false positives.
- Gradle wrapper (8.10.2, with `distributionSha256Sum` verification),
  `.gitignore` and `.gitattributes`.

### Changed
- Migrated from the legacy Extender API to the Montoya API. Findings are raised
  as `AuditIssue` objects (severity, confidence, background, remediation
  background, evidence) and appear in the Burp Dashboard and Site map alongside
  Burp's own checks.
- Three purpose-built scan checks on the current Montoya scan-check API
  (montoya-api 2026.7):
  - `SapPassiveScanCheck` - `PassiveScanCheck`, registered `PER_REQUEST`
    (SAP fingerprints, SAP-scoped cookie flags, verbose error disclosure).
  - `SapHostScanCheck` - `ActiveScanCheck`, registered `PER_HOST`, so the
    endpoint catalog and CVE probes run exactly once per host (Burp handles the
    scheduling).
  - `SapInsertionPointScanCheck` - `ActiveScanCheck`, registered
    `PER_INSERTION_POINT`, acting only on SAP-specific parameter names.
- Active checks issue their requests through the scan-task `Http` object so Burp
  links, scopes and throttles them with the audit.
- Reflected XSS probe uses a random marker instead of a static payload.
- Build targets Java 17 with a `compileOnly` Montoya dependency.

### Removed
- The deprecated `registerScanCheck(ScanCheck)` registration path.
- The legacy Extender API code (`BurpExtender`, `ScanController`, `WaSAPPanel`,
  `modules/*`) and the bundled `burp-extender-api` JAR, including the generic
  XSS / SQLi / traversal fuzzer, custom UI panel, context menu and CSV export
  that duplicated Burp Scanner's built-in functionality. The build declares
  Montoya only.

## [1.x] - legacy (pre-Montoya)

- Context-menu driven enumeration of ~50 SAP endpoints.
- Generic XSS / SQLi / traversal fuzzer.
- Custom Swing UI panel with CSV export.
- Built on the legacy `burp-extender-api` 2.3.
