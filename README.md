# WaSAP - Web Application SAP Enumerator

## Description
Simple burp plugin that checks for known endpoints and misconfigurations in SAP applications.

## Features
- **Extensive Enumeration**: Probes over 50+ known SAP endpoints (e.g., `/nwa`, `/irj/portal`, Fiori, Neptune, Visual Composer, OData).
- **Version Detection**: Extracts SAP NetWeaver version from HTTP headers and flags potential vulnerabilities (e.g., ICMAD).
- **Knowledge Base Integration**:
    - **Credential Suggester**: Suggests default credentials (e.g., SAP*/06071992) when login portals are detected.
    - **RECON Detection**: Checks for CVE-2020-6287 (`/CTCWebService/CTCWebServiceBean`).
    - **Invoker Detection**: Checks for exposed Invoker Servlets (CVE-2010-5326).
    - **Visual Composer**: Checks for CVE-2025-31324 endpoint.
    - **OData Enumeration**: Scans for exposed OData Service Catalogs.
- **Active Fuzzing**:
    - **Basic Injection**: probes parameters for XSS and SQLi errors.
- **Tech Detection**: Automatically detects SAP UI5 versions.
- **Security Checks**:
  - **CSRF Tokens**: Checks for missing or exposed CSRF tokens.
  - **Cookie Security**: Flags missing `Secure` and `HttpOnly` attributes.
  - **Active Scanning**: Probes for Reflected XSS (`HypR3Http.dll`) and RTMF misconfigurations.
- **Site Map Integration**: Automatically adds valid findings to the Burp Suite Site Map.
- **Interactive UI**:
  - Status code coloring.
  - Sortable results table.
  - Context menu (Copy URL, Open in Browser, Export to CSV).
  - "Clear Results" button.

## Installation
1. Download `WaSAP.jar` from the [releases page](https://github.com/portswigger/wasap/releases).
2. Open **Burp Suite**.
3. Navigate to **Extender** > **Extensions**.
4. Click **Add**.
5. Select **Extension type: Java**.
6. Select the downloaded `WaSAP.jar` file.

## Usage
1. Right-click on any request in the **Proxy** or **Target** tab.
2. Select **Enumerate SAP Endpoints** from the context menu.
3. Navigate to the **WaSAP** tab to view real-time results.
4. Valid findings (200 OK) will also appear in your **Target Site Map**.

## Build from Source
```bash
# Clone the repository
git clone https://github.com/portswigger/wasap.git

# Build with Gradle (if configured) or Manually
mkdir build
javac -cp "lib/burp-extender-api-2.3.jar" -d build src/main/java/wasap/*.java src/main/java/wasap/modules/*.java
jar cf WaSAP.jar -C build .
```

## Disclaimer
This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse or damage caused by this tool.

---
**Version:** 2.5.1
**Author:** Gjoko Krstic  
**Powered by Silly Security Inc.**
