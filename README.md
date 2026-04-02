# SBOM Focus: Vulnerability Analysis & Comparison Suite

A comprehensive collection of tools to parse, analyze, and compare vulnerability scan results for CycloneDX SBOM (Software Bill of Materials) files, specifically optimized for container image security and compliance research.

## 📁 Project Structure

```text
.
├── 🚀 Core Tools
│   ├── compare_osv_grype.py     # Scanner consensus (OSV vs Grype)
│   ├── query_osv_purl.py        # Batch OSV API scanning
│   ├── parse_sbom_cdxlib.py     # SBOM visualization & layer analysis
│   └── compare_purl_cpe_query.py # Triplet lookup (NVD, OSV, CIRCL)
├── 📚 Supporting Material/
│   ├── CRA_vulnerability_management_research.md # EU CRA compliance research
│   ├── layer_analysis_strategy.md              # SBOM layering strategy
│   └── syft_dependency_graph_insight.md        # Syft-specific insights
├── 📦 Sample Data/
│   ├── insecure-app-image-sbom-cyclonedx.json  # Reference SBOM
│   ├── compare_purl_cpe_query_*.json          # Cached API lookups
│   └── insecure-app-*-osv-vulns.json           # Scan results
└── 🛠 Utilities
    ├── grype-package-summary.tmpl              # Template for reporting
    └── insecure-app-repo-generate-sbom.sh      # SBOM generation script
```

## 🚀 Core Tools

| Category | Script | Description |
| :--- | :--- | :--- |
| **Consensus** | `compare_osv_grype.py` | Generates a Markdown report (`compare_osv_grype.md`) showing agreement between scanners. |
| **Scanning** | `query_osv_purl.py` | Performs batch OSV API scans of all PURLs in an SBOM with Optional Vulners enrichment. |
| **Analysis** | `parse_sbom_cdxlib.py` | Visualizes container layer stacking, ecosystem breakdown, and identifier coverage using `rich`. |
| **On-Demand** | `compare_purl_cpe_query.py` | Triplet comparison: compares NVD, OSV, and CIRCL data for a specific PURL or CPE. |

## 📚 Research & Supporting Materials

The repository contains extensive research documentation and technical advisories located in the `Supporting Material` directory:

- **[EU Cyber Resilience Act — Deep Research](Supporting%20Material/CRA_vulnerability_management_research.md)**: A comprehensive guide to the CRA's vulnerability management requirements (Regulation EU 2024/2847).
- **[Layer Analysis Strategy](Supporting%20Material/layer_analysis_strategy.md)**: Documentation on analyzing SBOMs through the lens of container layer stacking.
- **[Syft Dependency Graph Insights](Supporting%20Material/syft_dependency_graph_insight.md)**: Technical notes on how Syft handles dependency relationships.
- **Official Publications**:
  - *Commission guidance on the application of CRA* (PDF)
  - *ENISA Technical Advisory - Package Managers* (PDF)
  - *SBOM Analysis - Towards an Implementation Guide* (PDF)

## 📦 Sample Data

This repository includes reference SBOMs and pre-computed scan results for testing:

- `insecure-app-image-sbom-cyclonedx.json`: A full CycloneDX 1.6 SBOM for an insecure container image.
- `insecure-app-repo-sbom-cyclonedx.json`: A source-code SBOM generated with Syft.
- `compare_purl_cpe_query_*.json`: Cached raw responses from NVD, OSV, and CIRCL APIs for auditing.

## 🛠 Prerequisites

- Python 3.10+
- `cyclonedx-python-lib`
- `rich`
- `pandas`
- `requests`
- `python-dotenv`

## 📦 Installation

```bash
pip install cyclonedx-python-lib rich pandas requests python-dotenv
```

## ⚙️ Configuration

Create a `.env` file in the root directory to enable API-dependent features:

```env
# Optional: Used by query_osv_purl.py for EPSS/CVSS enrichment
VULNERS_API_KEY=your_api_key_here
```

## 📖 Usage

### 1. SBOM Visual Analysis

Analyze a CycloneDX JSON file and visualize layer stacking:

```bash
python3 parse_sbom_cdxlib.py [path_to_sbom.json] --show-deps
```

### 2. Multi-Scanner Comparison (OSV vs Grype)

Generate a Markdown report (`compare_osv_grype.md`) showing agreement between scanners:

```bash
python3 compare_osv_grype.py
```

> [!TIP]
> This script automatically refreshes OSV and Grype data if the local files are stale.

### 3. Batch OSV Scanning

Scan all packages in an SBOM and save results to JSON:

```bash
python3 query_osv_purl.py [path_to_sbom.json]
```

### 4. Triplet Lookup (NVD vs OSV vs CIRCL)

Compare a specific package identifier across three major databases:

```bash
python3 compare_purl_cpe_query.py
```

*(Edit the `cpe_value` and `purl_value` variables in the script for on-demand lookups)*

### Generating SBOM with Syft

To generate an SBOM for the local source code:

```bash
./insecure-app-repo-generate-sbom.sh
```

## 📊 Output Examples

The tools provide a visual representation of scanner agreement and EPSS (Exploit Prediction Scoring System) scores:

```text
  ┌─ golang.org/x/crypto@v0.37.0
  │ OG
  │ ✔✘ CVE-2025-47913         HIGH     7.5  EPSS:0.00039  ↳ O:GO-2025-4116
  │ ✔✔ CVE-2025-47914         MEDIUM   5.3  EPSS:0.00021  ↳ O:GHSA-f6x5-jh6r-wrfv,...
  └───────────────────────────────────────────────────────────────────
```

## 📄 License

MIT
