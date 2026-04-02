#!/usr/bin/env python3
"""
compare_scanners.py — Compare vulnerability scan results from OSV, Grype, and Vulners.

Reads three JSON scan results and produces console reports:
  1. Package Inventory — which scanners saw which PURLs.
  2. Vulnerability Matrix — per-package CVE/GHSA comparison across scanners,
     with provenance showing original bulletin IDs that matched each CVE.

Usage:  python compare_scanners.py
"""

import datetime
import json
import os
import re
import subprocess
import sys
import urllib.parse
from collections import defaultdict

# ── Input files (all derived from the same SBOM) ─────────────────────────
SBOM_FILE = "insecure-app-image-sbom-cyclonedx.json"
OSV_FILE = "insecure-app-image-sbom-cyclonedx-osv-vulns.json"
GRYPE_FILE = "insecure-app-image-sbom-cyclonedx-grype-output.json"


# ── colour helpers (ANSI 256) ─────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BG_DARK = "\033[48;5;236m"


USE_COLOR = True


def col(text, colour):
    if not USE_COLOR:
        return text
    return f"{colour}{text}{RESET}"


def is_today(filepath):
    """Check if the file was modified today."""
    if not os.path.exists(filepath):
        return False
    mtime = os.path.getmtime(filepath)
    return datetime.date.fromtimestamp(mtime) == datetime.date.today()


# ── PURL helpers ──────────────────────────────────────────────────────────


def normalise_purl(purl: str) -> str:
    """Strip qualifiers (?arch=… &distro=…) from a PURL to get a canonical key."""
    return purl.split("?")[0]


def name_version_from_purl(purl: str):
    """Extract (name, version) from a PURL like pkg:pypi/foo@1.2.3."""
    base = normalise_purl(purl)
    # Remove the pkg:type/ prefix
    # e.g. pkg:deb/ubuntu/binutils@2.34-6ubuntu1.11  →  ubuntu/binutils@2.34-6ubuntu1.11
    parts = base.split("/", 1)  # ['pkg:deb', 'ubuntu/binutils@2.34-6ubuntu1.11']
    if len(parts) < 2:
        return (base, "")

    purl_type = parts[0]
    remainder = parts[1]  # 'ubuntu/binutils@2.34-6ubuntu1.11'
    if "@" in remainder:
        name_part, version = remainder.rsplit("@", 1)
    else:
        name_part, version = remainder, ""

    name_part = urllib.parse.unquote(name_part)
    version = urllib.parse.unquote(version)

    # Preserve namespace for ecosystems that use it as part of the package name
    if purl_type in ("pkg:golang", "pkg:npm", "pkg:github"):
        name = name_part
    else:
        # last segment of the name path is the package name
        name = name_part.rsplit("/", 1)[-1]

    return (name, version)


def normalize_version(v: str) -> str:
    """Strip 'v' or 'go' prefixes for matching."""
    if not v:
        return ""
    v = v.strip().lower()
    if v.startswith("v"):
        v = v[1:]
    if v.startswith("go"):
        v = v[2:]
    return v


# ── Loaders ───────────────────────────────────────────────────────────────


def load_sbom(path: str):
    """
    Load the master list of components from the original CycloneDX SBOM.
    Returns:
        raw_count: int
        packages: { normalised_purl: { "purl", "name", "version", "cpe" } }
    """
    with open(path) as f:
        data = json.load(f)

    packages = {}
    components = data.get("components", [])
    raw_count = len(components)

    for comp in components:
        purl_raw = comp.get("purl", "")
        if not purl_raw:
            continue
        purl = normalise_purl(purl_raw)
        packages[purl] = {
            "purl": purl_raw,
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "cpe": comp.get("cpe", ""),
        }
    return raw_count, packages


def load_osv(path: str):
    """
    Returns:
        packages: { normalised_purl: { "purl", "name", "version" } }
        vulns:    { normalised_purl: { vuln_id: { "id", "severity", "cvss", "epss",
                                                   "sourceAdvisories": [...] } } }
    """
    with open(path) as f:
        data = json.load(f)

    packages = {}
    vulns = defaultdict(dict)

    for pkg in data.get("packages", []):
        purl_raw = pkg["purl"]
        purl = normalise_purl(purl_raw)
        packages[purl] = {
            "purl": purl_raw,
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
        }
        for v in pkg.get("vulnerabilities", []):
            vid = v["id"].upper()
            vulns[purl][vid] = {
                "id": vid,
                "severity": v.get("severity"),
                "cvss": v.get("cvss"),
                "epss": v.get("epss"),
                "sourceAdvisories": v.get("sourceAdvisories", []),
            }
    return packages, vulns


def load_grype(path: str):
    """
    Returns:
        packages: { normalised_purl: { "purl", "name", "version" } }
        vulns:    { normalised_purl: { vuln_id: { "id", "severity", "cvss", "epss",
                                                   "sourceAdvisories": [...] } } }

    Parses CycloneDX JSON output from Grype.
    - All components are collected from .components[]
    - Vulnerabilities are collected from .vulnerabilities[] and mapped via .affects[]
    """
    with open(path) as f:
        data = json.load(f)

    packages = {}
    vulns = defaultdict(dict)

    # map bom-ref -> purl
    ref_map = {}

    # 1. Collect all components (inventory)
    for comp in data.get("components", []):
        purl_raw = comp.get("purl", "")
        if not purl_raw:
            continue

        purl = normalise_purl(purl_raw)
        bom_ref = comp.get("bom-ref")
        if bom_ref:
            ref_map[bom_ref] = purl

        packages[purl] = {
            "purl": purl_raw,
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
        }

    # 2. Collect all vulnerabilities
    for v in data.get("vulnerabilities", []):
        raw_id = v.get("id", "").upper()

        # Extract source ID from properties (e.g., security:vulnerability:source:id)
        source_id = None
        for prop in v.get("properties", []):
            if prop.get("name") == "security:vulnerability:source:id":
                source_id = prop.get("value", "").upper()
                break

        # Pick the best primary identifier (CVE preferred)
        if source_id and source_id.startswith("CVE-"):
            vid = source_id
        elif raw_id.startswith("CVE-"):
            vid = raw_id
        elif source_id:
            vid = source_id
        else:
            vid = raw_id

        # Determine severity, CVSS, and EPSS from ratings
        severity = None
        cvss_val = None
        epss_val = None

        for rating in v.get("ratings", []):
            method = rating.get("method")
            source_name = rating.get("source", {}).get("name", "")

            # Likely a CVSS score
            if method and method.startswith("CVSS"):
                if cvss_val is None:
                    cvss_val = rating.get("score")
                if severity is None:
                    severity = rating.get("severity")

            # Likely an EPSS score
            if (
                source_name == "FIRST"
                or "epss" in str(rating.get("source", {}).get("url", "")).lower()
            ):
                epss_val = rating.get("score")

        # Fallback for severity if not found in ratings
        if severity is None:
            # check root properties or just leave it
            pass

        # Map to all affected components
        for affected in v.get("affects", []):
            ref = affected.get("ref")
            purl = ref_map.get(ref)
            if not purl:
                # Sometimes ref is the PURL itself
                if ref and ref.startswith("pkg:"):
                    purl = normalise_purl(ref)
                else:
                    continue

            # Record vulnerability
            if vid not in vulns[purl]:
                # track original ID as provenance (advisory)
                provenance = [raw_id] if raw_id != vid else []
                if source_id and source_id != vid and source_id != raw_id:
                    provenance.append(source_id)

                vulns[purl][vid] = {
                    "id": vid,
                    "severity": severity,
                    "cvss": cvss_val,
                    "epss": epss_val,
                    "sourceAdvisories": sorted(list(set(provenance))),
                }

    return packages, vulns




# ── Build reverse map (name,version) → PURL ──────────────────────────────


def build_name_version_to_purl(all_purls: set):
    """Given a set of normalised PURLs, return a dict mapping (name, normalized_version) → purl."""
    mapping = {}
    for purl in all_purls:
        name, version = name_version_from_purl(purl)
        norm_v = normalize_version(version)
        mapping[(name, norm_v)] = purl
    return mapping


# ── Severity ordering for display ─────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4}


def sev_sort_key(vid_info):
    """Sort by severity (CRITICAL first), then by CVE id."""
    sev = (vid_info.get("severity") or "").upper()
    return (SEV_ORDER.get(sev, 99), vid_info.get("id", ""))


def sev_colour(severity):
    if not severity:
        return DIM
    s = severity.upper()
    if s == "CRITICAL":
        return RED + BOLD
    elif s == "HIGH":
        return RED
    elif s == "MEDIUM":
        return YELLOW
    elif s == "LOW":
        return DIM
    return DIM


# ── Printing helpers ──────────────────────────────────────────────────────

LINE_W = 120


def hline(char="─"):
    # Drop ASCII bars in Markdown for compliance, but keep a simple line for console if needed
    # Better yet, just skip them or use a markdown horizontal rule
    pass


def section_header(title):
    print()
    print(f"## {title}")
    print()


def check_mark(detected: bool):
    return col("✔", GREEN) if detected else col("✘", RED)


# ── Ecosystem helpers ─────────────────────────────────────────────────────

ECOSYSTEM_LABELS = {
    "pypi": "Python (PyPI)",
    "golang": "Go",
    "deb": "Debian/Ubuntu (deb)",
    "rpm": "RPM",
    "npm": "npm",
    "maven": "Maven/Java",
    "nuget": "NuGet/.NET",
    "cargo": "Rust (Cargo)",
    "gem": "Ruby (Gem)",
}


def ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem key from a PURL like pkg:pypi/foo@1.2.3 → 'pypi'."""
    if purl.startswith("pkg:"):
        purl_type = purl[4:].split("/", 1)[0]  # 'pypi', 'deb', 'golang', …
        return purl_type
    return "other"


def ecosystem_label(eco: str) -> str:
    return ECOSYSTEM_LABELS.get(eco, eco)


# ── Main logic ────────────────────────────────────────────────────────────


def run_report():
    # 0. Ensure OSV data freshness
    if not is_today(OSV_FILE):
        print(col(f"🔄 OSV data is stale or missing ({OSV_FILE}).", YELLOW))
        print(col(f"   Refreshing via query_osv_purl.py {SBOM_FILE}...", DIM))
        try:
            subprocess.run(["python3", "query_osv_purl.py", SBOM_FILE], check=True)
            print(col("✅ OSV data refreshed.", GREEN))
        except subprocess.CalledProcessError as e:
            print(col(f"❌ Failed to refresh OSV data: {e}", RED))

    # 1. Ensure Grype data freshness
    if not is_today(GRYPE_FILE):
        print(col(f"🔄 Grype data is stale or missing ({GRYPE_FILE}).", YELLOW))
        print(
            col(f"   Refreshing via 'grype sbom:{SBOM_FILE} -o cyclonedx-json'...", DIM)
        )
        try:
            with open(GRYPE_FILE, "w") as f:
                subprocess.run(
                    ["grype", f"sbom:{SBOM_FILE}", "-o", "cyclonedx-json", "--by-cve"],
                    stdout=f,
                    check=True,
                )
            print(col("✅ Grype data refreshed.", GREEN))
        except subprocess.CalledProcessError as e:
            print(col(f"❌ Failed to refresh Grype data: {e}", RED))

    # Load the base SBOM
    sbom_raw_count, sbom_pkgs = load_sbom(SBOM_FILE)
    sbom_purls = set(sbom_pkgs.keys())

    # Load each scanner
    osv_pkgs, osv_vulns = load_osv(OSV_FILE)
    grype_pkgs, grype_vulns = load_grype(GRYPE_FILE)

    # 1. Build Canonical PURL Mapping
    # Logic: for each (name, norm_v), pick one PURL as primary (preferably from SBOM).
    canonical_map = {}  # raw_purl -> primary_purl
    nv_to_primary = {}  # (name, norm_v) -> primary_purl

    # First pass: PURLs from SBOM are preferred as sources of truth
    for purl in sorted(sbom_purls):
        name, version = name_version_from_purl(purl)
        norm_v = normalize_version(version)
        nv = (name, norm_v)
        if nv not in nv_to_primary:
            nv_to_primary[nv] = purl
        canonical_map[purl] = nv_to_primary[nv]

    # Second pass: Include PURLs from scanners
    all_raw_purls = sbom_purls | set(osv_pkgs.keys()) | set(grype_pkgs.keys())
    for purl in sorted(all_raw_purls):
        if purl in canonical_map:
            continue
        name, version = name_version_from_purl(purl)
        norm_v = normalize_version(version)
        nv = (name, norm_v)
        if nv not in nv_to_primary:
            nv_to_primary[nv] = purl
        canonical_map[purl] = nv_to_primary[nv]

    # 2. Re-key everything to primary PURLs
    def rekey_by_primary(pkgs_dict, vulns_dict):
        new_pkgs = {}
        new_vulns = defaultdict(dict)
        for purl, info in pkgs_dict.items():
            primary = canonical_map.get(purl, purl)
            if primary not in new_pkgs:
                new_pkgs[primary] = info
            # merge vulns
            if purl in vulns_dict:
                for vid, vinfo in vulns_dict[purl].items():
                    new_vulns[primary][vid] = vinfo
        return new_pkgs, new_vulns

    osv_scanned_pkgs, osv_vulns = rekey_by_primary(osv_pkgs, osv_vulns)
    grype_scanned_pkgs, grype_vulns = rekey_by_primary(grype_pkgs, grype_vulns)

    # ── Global Vulnerability ID Consolidation ─────────────────────────────
    # Scanners often report the same issue with different IDs (CVE vs GHSA).
    # We build an alias map to unify them under a single canonical ID.

    # 1. Build local alias maps per package
    all_purls = set(nv_to_primary.values())
    package_alias_maps = defaultdict(dict)  # { purl: { alias_id: canonical_id } }

    for purl in all_purls:
        scanner_results = [
            osv_vulns[purl],
            grype_vulns[purl],
        ]
        alias_map = package_alias_maps[purl]

        for vmap in scanner_results:
            for vid, vinfo in vmap.items():
                for alias in vinfo.get("sourceAdvisories", []):
                    # Canonical ID selection: prefer CVE over anything else
                    if not vid.startswith("CVE-") and alias.startswith("CVE-"):
                        canon, other = alias, vid
                    else:
                        canon, other = vid, alias

                    # If we already have a mapping for this alias, ensure they point to the same canon
                    if other in alias_map and alias_map[other] != canon:
                        # Existing mapping exists; prefer CVE
                        if not alias_map[other].startswith("CVE-") and canon.startswith(
                            "CVE-"
                        ):
                            alias_map[other] = canon
                    else:
                        alias_map[other] = canon

    # 2. Re-map all scanners to use the consolidated IDs
    def consolidate_vulns(vulns_dict):
        new_vulns = defaultdict(dict)
        for purl, vmap in vulns_dict.items():
            alias_map = package_alias_maps[purl]
            for vid, vinfo in vmap.items():
                canon = alias_map.get(vid, vid)

                if canon not in new_vulns[purl]:
                    new_vulns[purl][canon] = vinfo.copy()
                    new_vulns[purl][canon]["id"] = canon
                else:
                    # Merge info: keep higher severity / score
                    target = new_vulns[purl][canon]
                    for key in ("cvss", "epss", "severity"):
                        if vinfo.get(key) is not None and target.get(key) is None:
                            target[key] = vinfo[key]

                # Accumulate source advisories (original IDs)
                target = new_vulns[purl][canon]
                advisories = set(target.get("sourceAdvisories", []))
                advisories.update(vinfo.get("sourceAdvisories", []))
                if vid != canon:
                    advisories.add(vid)
                target["sourceAdvisories"] = sorted(
                    [a for a in advisories if a != canon]
                )

        return new_vulns

    osv_vulns = consolidate_vulns(osv_vulns)
    grype_vulns = consolidate_vulns(grype_vulns)

    # Master list of PURLs: all primary PURLs
    all_purls = set(nv_to_primary.values())

    # Merge all package info
    all_pkg_info = {}
    for purl in all_purls:
        info = (
            sbom_pkgs.get(purl)
            or osv_scanned_pkgs.get(purl)
            or grype_scanned_pkgs.get(purl)
            or {}
        )
        all_pkg_info[purl] = info

    # Separate vulnerable vs clean PURLs (using merged data)
    vuln_purls = set()
    clean_purls = set()
    for purl in all_purls:
        if (
            osv_vulns.get(purl)
            or grype_vulns.get(purl)
        ):
            vuln_purls.add(purl)
        else:
            clean_purls.add(purl)

    # Group by ecosystem
    eco_groups_vuln = defaultdict(list)
    for purl in sorted(vuln_purls, key=lambda p: name_version_from_purl(p)):
        eco = ecosystem_from_purl(purl)
        eco_groups_vuln[eco].append(purl)

    # Ordered ecosystems: known ones first, then the rest
    known_order = [
        "pypi",
        "deb",
        "golang",
        "npm",
        "maven",
        "cargo",
        "gem",
        "rpm",
        "nuget",
    ]

    eco_order_vuln = [e for e in known_order if e in eco_groups_vuln]
    eco_order_vuln += sorted(set(eco_groups_vuln.keys()) - set(known_order))

    # Pre-compute global stats
    osv_total = set()
    grype_total = set()
    osv_detected = set(osv_vulns.keys())
    grype_detected = set(grype_vulns.keys())

    for purl in all_purls:
        osv_total.update(osv_vulns.get(purl, {}).keys())
        grype_total.update(grype_vulns.get(purl, {}).keys())

    # Build active sets for consensus and stats
    active_scanner_sets = [("OSV", osv_total), ("Grype", grype_total)]

    sets = [s[1] for s in active_scanner_sets]

    # Consensus: present in ALL active scanners
    if sets:
        consensus = sets[0].copy()
        for s in sets[1:]:
            consensus &= s
    else:
        consensus = set()

    at_least_two = set()
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            at_least_two |= sets[i] & sets[j]

    all_vuln_ids = set()
    for s in sets:
        all_vuln_ids.update(s)

    # ── Report Generation ────────────────────────────────────────────────
    print("# Vulnerability Comparison Report")

    section_header("Summary")
    print(f"  SBOM Components (Raw): {sbom_raw_count}")
    print(f"  Deduplicated PURLs:    {len(all_purls)}")
    print(f"  Clean (0 vulns):       {len(clean_purls)}")
    print(f"  Vulnerable:            {len(vuln_purls)}")
    print()
    # SUMMARY table rows
    print(
        f"  {col('Scanner', BOLD):<18} | {col('Pkgs Scanned', BOLD):<18} | {col('Pkgs w/ Vulns', BOLD):<18} | {col('Total Vuln IDs', BOLD):<15}"
    )
    # Removing hline in Markdown for cleaner output
    print(
        f"  {'OSV':<18} | {len(osv_scanned_pkgs):<18} | {len(osv_detected):<18} | {len(osv_total):<15}"
    )
    print(
        f"  {'Grype':<18} | {len(grype_scanned_pkgs):<18} | {len(grype_detected):<18} | {len(grype_total):<15}"
    )

    cve_count = sum(1 for v in all_vuln_ids if v.startswith("CVE-"))
    ghsa_count = sum(1 for v in all_vuln_ids if v.startswith("GHSA-"))
    other_count = len(all_vuln_ids) - cve_count - ghsa_count

    agree_label = f"All {len(sets)} agree:"
    print(
        f"  {col(agree_label, GREEN)} {len(consensus)}    "
        f"{col('≥2 agree:', BOLD)} {len(at_least_two)}    "
        f"{col('Total:', BOLD)} {len(all_vuln_ids)}  "
        f"{col(f'(CVE:{cve_count} GHSA:{ghsa_count} Other:{other_count})', DIM)}"
    )

    # Exclusive logic
    excl_parts = []
    for name, vset in active_scanner_sets:
        others = [s[1] for s in active_scanner_sets if s[0] != name]
        excl_count = len(vset.difference(*others)) if others else len(vset)
        excl_parts.append(f"{name}:{excl_count}")

    print(f"  {col('Exclusive to:', DIM)} {'  '.join(excl_parts)}")

    # ── Section 2: Package Inventory details ──────────────────────────────

    # ── Section 2: Package Inventory details ──────────────────────────────

    # 2a. Vulnerable Packages
    section_header("VULNERABLE PACKAGES — [O]SV [G]rype findings")

    for i, eco in enumerate(eco_order_vuln):
        purls = eco_groups_vuln[eco]
        if i > 0:
            print()
        print(col(f"  ▸ {ecosystem_label(eco)} ({len(purls)} packages)", BOLD + WHITE))

        for purl in purls:
            # Marks on the left (4 indent + 3 marks + 2 space + 70 purl = 79)
            dp = purl if len(purl) <= 70 else purl[:67] + "..."
            marks = [
                check_mark(purl in osv_detected),
                check_mark(purl in grype_detected),
            ]

            print(f"    {''.join(marks)}  {dp}")

    # ── Section 4: Vulnerability Detail by ecosystem ──────────────────────

    # ── Section 4: Vulnerability Detail by ecosystem ──────────────────────
    section_header("VULNERABILITY DETAIL — All Scanner Findings")
    print("  Shows all vulnerabilities discovered and scanner agreement status.")

    # Dynamic column header for detail section
    detail_header = f"  {col('O', BOLD)}SV {col('G', BOLD)}rype"
    detail_header += f"        {col('EPSS', MAGENTA)}  {col('↳ provenance', MAGENTA)}"

    print(detail_header)

    for i, eco in enumerate(eco_order_vuln):
        purls = eco_groups_vuln[eco]
        # Check if any package in this eco has vulnerabilities
        has_any = False
        for purl in purls:
            if (
                purl in osv_detected
                or purl in grype_detected
            ):
                has_any = True
                break
        if not has_any:
            continue

        if i > 0:
            print()
        print(col(f"  ━━ {ecosystem_label(eco)} ━━", BOLD + CYAN))

        for purl in purls:
            osv_v = osv_vulns.get(purl, {})
            grype_v = grype_vulns.get(purl, {})

            all_vids = (
                set(osv_v.keys())
                | set(grype_v.keys())
            )
            if not all_vids:
                continue

            info = all_pkg_info.get(purl, {})
            display_name = info.get("name", purl) or purl
            display_ver = info.get("version", "")
            to_display = sorted(all_vids)

            def vid_sort_key(vid):
                for source in (osv_v, grype_v):
                    if vid in source:
                        sev = (source[vid].get("severity") or "").upper()
                        return (
                            0 if vid.startswith("CVE-") else 1,
                            SEV_ORDER.get(sev, 99),
                            vid,
                        )
                return (2, 99, vid)

            print(col(f"  ┌─ {display_name}@{display_ver}", BOLD + WHITE))

            # Print indicator header for the vulns
            indicator_labels = [col("O", BOLD), col("G", BOLD)]
            print(f"  │ {''.join(indicator_labels)}")

            for vid in sorted(to_display, key=vid_sort_key):
                in_osv = vid in osv_v
                in_grype = vid in grype_v

                severity = cvss = epss = None
                for source in (osv_v, grype_v):
                    if vid in source:
                        if not severity:
                            severity = source[vid].get("severity")
                        if cvss is None:
                            cvss = source[vid].get("cvss")
                        if epss is None:
                            epss = source[vid].get("epss")

                sev_str = (severity or "?").upper()
                sev_display = col(f"{sev_str:<6}", sev_colour(severity))
                cvss_display = f"{cvss:.1f}" if cvss is not None else " - "
                try:
                    raw_epss = f"EPSS:{float(epss):.5f}" if epss is not None else " " * 12
                except (ValueError, TypeError):
                    raw_epss = f"EPSS:{str(epss):<5}" if epss is not None else " " * 12
                
                epss_display = col(raw_epss, CYAN) if epss is not None else raw_epss

                # Build dynamic marks
                marks_list = [check_mark(in_osv), check_mark(in_grype)]
                marks = "".join(marks_list)

                prov_bits = []
                for label, src, flag in [
                    ("O", osv_v, in_osv),
                    ("G", grype_v, in_grype),
                ]:
                    if flag and vid in src and src[vid].get("sourceAdvisories"):
                        prov_bits.append(
                            f"{label}:{','.join(src[vid]['sourceAdvisories'])}"
                        )
                prov_content = " | ".join(prov_bits)
                if len(prov_content) > 25:
                    prov_content = prov_content[:22] + "..."

                prov_str = col(f"  ↳ {prov_content}", MAGENTA) if prov_bits else ""

                print(
                    f"  │ {marks} {vid:<22} {sev_display:<9} {cvss_display:>5}  {epss_display}{prov_str}"
                )

            # Adjusted width for two scanners
            print(f"  └{'─' * 67}")


class DualOutput:
    """Redirects stdout to both the terminal (colors) and a file (no colors)."""

    def __init__(self, file_path):
        self.terminal = sys.stdout
        self.file = open(file_path, "w", encoding="utf-8")
        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.buffer = ""

    def write(self, message):
        self.terminal.write(message)
        # Add to buffer and write completed lines rstripped
        self.buffer += self.ansi_escape.sub("", message)
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self.file.write(line.rstrip() + "\n")

    def flush(self):
        self.terminal.flush()
        self.file.flush()

    def close(self):
        if self.buffer:
            self.file.write(self.buffer.rstrip() + "\n")
        self.file.close()


def main():
    report_file = "compare_osv_grype.md"
    dual_output = DualOutput(report_file)
    sys.stdout = dual_output

    try:
        run_report()
    finally:
        sys.stdout = dual_output.terminal
        dual_output.close()
        print(col(f"✅ Report saved to {report_file}", GREEN))


if __name__ == "__main__":
    main()
