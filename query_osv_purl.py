#!/usr/bin/env python3
"""
OSV Vulnerability Scanner for CycloneDX SBOM PURLs.

Reads all PURLs from a CycloneDX SBOM JSON file, queries the OSV API
(https://api.osv.dev/v1/querybatch) for known vulnerabilities, then
fetches full details to resolve CVE aliases.

Deduplicates advisories that map to the same CVE. Displays a formatted
console table with:
  - Package PURL (with unique vuln count)
  - Primary Vuln ID (CVE preferred, GHSA fallback)
  - Source advisory IDs that map to it
"""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

# ── Configuration ────────────────────────────────────────────────────
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"  # GET /v1/vulns/{id}
BATCH_SIZE = 100  # queries per batch request
SBOM_FILE = "insecure-app-image-sbom-cyclonedx.json"

# ── Helpers ──────────────────────────────────────────────────────────


def load_purls(sbom_path: str) -> list[str]:
    """Extract unique PURLs from CycloneDX components."""
    with open(sbom_path, "r") as f:
        sbom = json.load(f)
    purls = []
    seen = set()
    for comp in sbom.get("components", []):
        purl = comp.get("purl")
        if purl and purl not in seen:
            purls.append(purl)
            seen.add(purl)
    return purls


def query_osv_batch(purls: list[str]) -> list[dict]:
    """
    Query OSV /v1/querybatch for a list of PURLs.
    Returns the 'results' array (one entry per query, in order).
    """
    queries = [{"package": {"purl": p}} for p in purls]
    payload = json.dumps({"queries": queries}).encode("utf-8")

    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    return body.get("results", [])


def fetch_vuln_details(vuln_id: str) -> dict:
    """Fetch full vulnerability details from /v1/vulns/{id}."""
    url = f"{OSV_VULN_URL}/{urllib.parse.quote(vuln_id, safe='')}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {"id": vuln_id}


def collect_all_ids(vuln: dict) -> dict:
    """
    Extract all identifiers from a vuln detail.
    Returns dict with keys: cves, ghsas (each a set of strings).
    """
    cves: set[str] = set()
    ghsas: set[str] = set()

    # Collect from id, aliases, related, upstream
    all_ids: list[str] = [vuln.get("id", "")]
    all_ids.extend(vuln.get("aliases", []))
    all_ids.extend(vuln.get("related", []))
    all_ids.extend(vuln.get("upstream", []))

    for ident in all_ids:
        if ident.startswith("CVE-"):
            cves.add(ident)
        elif ident.startswith("GHSA-"):
            ghsas.add(ident)

    return {"cves": cves, "ghsas": ghsas}


def canonical_id(ids_info: dict) -> str:
    """
    Pick the best primary identifier:
      1. CVE ID (first sorted)
      2. GHSA ID (first sorted)
      3. '-'
    """
    if ids_info["cves"]:
        return sorted(ids_info["cves"])[0]
    if ids_info["ghsas"]:
        return sorted(ids_info["ghsas"])[0]
    return "-"


def shorten_purl(purl: str, max_len: int = 60) -> str:
    """Shorten a PURL for display by truncating qualifiers."""
    if len(purl) > max_len:
        base = purl.split("?")[0]
        if len(base) > max_len:
            return base[: max_len - 3] + "..."
        return base
    return purl


def dedupe_vulns(
    vuln_id_list: list[str], vuln_details: dict[str, dict]
) -> list[tuple[str, list[str]]]:
    """
    Deduplicate a list of OSV vuln IDs into unique vulnerabilities.

    Returns a sorted list of (canonical_id, [source_advisory_ids]).
    Multiple advisories mapping to the same CVE are grouped together.
    When a single advisory (e.g. USN) maps to multiple CVEs, it is
    added as a source to each of those CVE groups.
    """
    # Map: canonical -> set of source advisory IDs
    groups: dict[str, set[str]] = {}

    for vid in vuln_id_list:
        detail = vuln_details.get(vid, {"id": vid})
        ids_info = collect_all_ids(detail)

        if ids_info["cves"]:
            # Advisory maps to one or more CVEs — add it to each CVE group
            for cve in ids_info["cves"]:
                if cve not in groups:
                    groups[cve] = set()
                groups[cve].add(vid)
        elif ids_info["ghsas"]:
            # No CVE, use first GHSA as canonical
            canon = sorted(ids_info["ghsas"])[0]
            if canon not in groups:
                groups[canon] = set()
            groups[canon].add(vid)
        else:
            # No CVE or GHSA — use the raw OSV id as its own group
            if vid not in groups:
                groups[vid] = set()
            groups[vid].add(vid)

    # Sort by canonical ID; build result
    result = []
    for canon in sorted(groups):
        sources = sorted(groups[canon])
        # Remove the canonical from sources if it's there (avoid redundancy)
        display_sources = [s for s in sources if s != canon]
        result.append((canon, display_sources))

    return result




# ── Main ─────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Query OSV API for CycloneDX SBOM PURLs."
    )
    parser.add_argument(
        "sbom_path", nargs="?", default=SBOM_FILE, help="Path to CycloneDX SBOM JSON"
    )
    parser.add_argument(
        "--all", action="store_true", help="Show clean packages in the console table"
    )
    args = parser.parse_args()

    sbom_path = args.sbom_path
    show_all = args.all

    # Load PURLs
    print(f"📦 Loading PURLs from: {sbom_path}")
    try:
        purls = load_purls(sbom_path)
    except FileNotFoundError:
        print(f"❌ File not found: {sbom_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        sys.exit(1)

    print(f"   Found {len(purls)} unique PURLs\n")

    if not purls:
        print("Nothing to scan.")
        return

    # ── Step 1: Query OSV batch to find which PURLs have vulns ───────
    purl_vuln_ids: dict[str, list[str]] = {}
    total_batches = (len(purls) + BATCH_SIZE - 1) // BATCH_SIZE

    for batch_idx in range(total_batches):
        start = batch_idx * BATCH_SIZE
        end = min(start + BATCH_SIZE, len(purls))
        batch_purls = purls[start:end]

        print(
            f"\r🔍 Querying OSV batch {batch_idx + 1}/{total_batches} "
            f"({start + 1}-{end} of {len(purls)})...",
            end="",
            flush=True,
        )

        try:
            results = query_osv_batch(batch_purls)
        except urllib.error.URLError as e:
            print(f"\n❌ API error on batch {batch_idx + 1}: {e}")
            results = [{"vulns": []} for _ in batch_purls]
        except Exception as e:
            print(f"\n❌ Unexpected error on batch {batch_idx + 1}: {e}")
            results = [{"vulns": []} for _ in batch_purls]

        for purl, result in zip(batch_purls, results):
            vuln_ids = [v.get("id") for v in result.get("vulns", []) if v.get("id")]
            if vuln_ids:
                purl_vuln_ids[purl] = vuln_ids

        if batch_idx < total_batches - 1:
            time.sleep(0.3)

    print("\n")

    if not purl_vuln_ids:
        print("✅ No vulnerabilities found for any PURL.")
        return

    # ── Step 2: Fetch full details for each unique vuln ID ───────────
    all_vuln_ids = set()
    for ids in purl_vuln_ids.values():
        all_vuln_ids.update(ids)

    print(f"📋 Fetching details for {len(all_vuln_ids)} unique vulnerabilities...")
    vuln_details: dict[str, dict] = {}
    fetched = 0

    for vid in sorted(all_vuln_ids):
        fetched += 1
        print(
            f"\r   {fetched}/{len(all_vuln_ids)} fetched...",
            end="",
            flush=True,
        )
        vuln_details[vid] = fetch_vuln_details(vid)
        time.sleep(0.1)

    print("\n")

    # ── Step 3: Deduplicate per package ────────────────────────────────
    # Build deduped results per package first, collect all canonical CVEs
    purl_deduped: list[tuple[str, list[tuple[str, list[str]]]]] = []
    all_canonical_cves: set[str] = set()
    total_unique = 0
    vuln_packages = 0

    for purl in purls:
        vuln_ids = purl_vuln_ids.get(purl, [])
        if vuln_ids:
            vuln_packages += 1
            deduped = dedupe_vulns(vuln_ids, vuln_details)
            total_unique += len(deduped)
            purl_deduped.append((purl, deduped))
            for canon, _ in deduped:
                if canon.startswith("CVE-"):
                    all_canonical_cves.add(canon)
        else:
            purl_deduped.append((purl, []))


    # ── Step 4: Build table rows ─────────────────────────────────────
    purl_col = "PURL"
    vuln_col = "Vulnerability"
    src_col = "Also reported as"

    # Row: (purl, vuln, sources) — empty tuple = separator
    rows: list[tuple[str, str, str]] = []

    for purl, deduped in purl_deduped:
        count = len(deduped)
        if count == 0 and not show_all:
            continue

        short = shorten_purl(purl)
        header = f"{short}  ({count} unique)"

        if count == 0:
            rows.append((header, "✅ CLEAN", "", "", "", ""))
        else:
            for i, (canon, sources) in enumerate(deduped):
                src_str = ", ".join(sources) if sources else ""
                display_purl = header if i == 0 else ""
                rows.append((display_purl, canon, src_str))

        # Separator between entries
        rows.append(("", "", ""))

    # Remove trailing separator
    if rows and rows[-1] == ("", "", ""):
        rows.pop()

    # ── Step 5: Print table ──────────────────────────────────────────
    w_purl = max(len(purl_col), max((len(r[0]) for r in rows), default=0))
    w_vuln = max(len(vuln_col), max((len(r[1]) for r in rows), default=0))
    w_src = max(len(src_col), max((len(r[2]) for r in rows), default=0))

    sep = f"+-{'-' * w_purl}-+-{'-' * w_vuln}-+-{'-' * w_src}-+"
    hdr = f"| {purl_col:<{w_purl}} | {vuln_col:<{w_vuln}} | {src_col:<{w_src}} |"

    raw_total = sum(len(v) for v in purl_vuln_ids.values())

    print(
        f"⚠️  {total_unique} unique vulnerabilities across "
        f"{vuln_packages} packages "
        f"(deduplicated from {raw_total} advisories)\n"
    )
    print(sep)
    print(hdr)
    print(sep)

    for purl_str, vid, src in rows:
        if purl_str == "" and vid == "" and src == "":
            print(
                f"|{'-' * (w_purl + 2)}+{'-' * (w_vuln + 2)}+{'-' * (w_src + 2)}|"
            )
        else:
            print(f"| {purl_str:<{w_purl}} | {vid:<{w_vuln}} | {src:<{w_src}} |")

    print(sep)
    print(
        f"\n📊 Summary: {total_unique} unique vulns in "
        f"{vuln_packages}/{len(purls)} packages"
    )

    # ── Step 6: Save results to JSON ─────────────────────────────────
    # step 6 now uses datetime imported at top

    json_output = {
        "meta": {
            "tool": "query_osv_purl",
            "sbomFile": sbom_path,
            "created": datetime.datetime.now().isoformat(),
            "totalPackages": len(purls),
            "affectedPackages": vuln_packages,
            "totalAdvisories": raw_total,
            "uniqueVulnerabilities": total_unique,
        },
        "packages": [],
    }

    for purl, deduped in purl_deduped:
        # Extract package name and version from PURL
        # purl format: pkg:type/namespace/name@version?qualifiers
        purl_base = purl.split("?")[0]  # strip qualifiers
        name_ver = purl_base.split("/")[-1]  # "name@version"
        pkg_name = name_ver.split("@")[0] if "@" in name_ver else name_ver
        pkg_version = name_ver.split("@")[1] if "@" in name_ver else ""

        pkg_entry = {
            "purl": purl,
            "name": pkg_name,
            "version": pkg_version,
            "uniqueVulnCount": len(deduped),
            "vulnerabilities": [],
        }

        for canon, sources in deduped:
            vuln_entry = {
                "id": canon,
                "sourceAdvisories": sources,
            }
            pkg_entry["vulnerabilities"].append(vuln_entry)

        json_output["packages"].append(pkg_entry)

    # Derive output filename from SBOM filename
    base = os.path.splitext(os.path.basename(sbom_path))[0]
    out_file = f"{base}-osv-vulns.json"
    with open(out_file, "w") as f:
        json.dump(json_output, f, indent=2)

    print(f"💾 Results saved to: {out_file}")


if __name__ == "__main__":
    main()
