import json
import time
import pandas as pd
import requests
from urllib.parse import urlencode

# API Base URLs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/query"
CIRCL_API_URL = "https://vulnerability.circl.lu/api/vulnerability/cpesearch"

# Filename prefix for saving raw responses
FILE_PREFIX = "compare_purl_cpe_query"


def save_raw_json(api_name, data):
    """Saves the raw JSON response to a file with the required prefix."""
    filename = f"{FILE_PREFIX}_{api_name}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"Saved raw response to {filename}")
    except Exception as e:
        print(f"Failed to save raw response for {api_name}: {e}")


cpe_value = "cpe:2.3:a:openssl:openssl:1.1.1f-1ubuntu2.24:*:*:*:*:*:*:*"
purl_value = "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.24?arch=amd64&distro=ubuntu-20.04"

""" cpe_value = "cpe:2.3:a:cryptography.io:cryptography:3.3.2:*:*:*:*:python:*:*"
purl_value = "pkg:pypi/cryptography@3.3.2" """

""" cpe_value = "cpe:2.3:a:golang:networking:v0.39.0:*:*:*:*:go:*:*"
purl_value = "pkg:golang/golang.org/x/net@v0.39.0" """

params_nvd = {"cpeName": cpe_value}


def get_nvd_data(url, params):
    start_time = time.time()
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
    except requests.exceptions.Timeout:
        print(f"Request to {url} timed out.")
        return {}, time.time() - start_time
    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code if http_err.response else None
        if status_code == 429:
            print(f"HTTP 429 Too Many Requests: Rate limit exceeded for {url}.")
        elif status_code == 403:
            print(f"HTTP 403 Forbidden: Access denied for {url}.")
        elif status_code == 400:
            print(f"HTTP 400 Bad Request: The request to {url} is malformed.")
        else:
            print(
                f"HTTP error occurred for {url}: {http_err} (Status code: {status_code})"
            )
        return {}, time.time() - start_time
    except requests.exceptions.RequestException as e:
        print(f"Request to {url} failed: {e}")
        return {}, time.time() - start_time

    cve_data = {}
    data = response.json()
    save_raw_json("nvd", data)
    if "vulnerabilities" in data:
        for vuln in data["vulnerabilities"]:
            cve_info = vuln.get("cve", {})
            cve_id = cve_info.get("id", "No CVE ID")
            if cve_id != "No CVE ID":
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_data[cve_id] = nvd_url
    else:
        print(f"No 'vulnerabilities' key in response from {url}")
    elapsed_time = time.time() - start_time
    return cve_data, elapsed_time


def get_osv_data(purl):
    start_time = time.time()
    url = OSV_API_URL
    payload = {"package": {"purl": purl}}
    cve_data = {}
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        save_raw_json("osv", data)
    except requests.exceptions.Timeout:
        print(f"Request to {url} timed out.")
        return {}, time.time() - start_time
    except requests.exceptions.RequestException as e:
        print(f"Request to {url} failed: {e}")
        return {}, time.time() - start_time

    if "vulns" in data:
        for vuln in data["vulns"]:
            vuln_id = vuln.get("id")
            osv_url = f"https://osv.dev/vulnerability/{vuln_id}"

            # Collect CVE IDs from multiple possible keys
            potential_cves = set()
            if vuln_id.startswith("CVE-"):
                potential_cves.add(vuln_id)

            # Look for CVEs in aliases, related, and upstream
            for source_key in ["aliases", "related", "upstream"]:
                source_list = vuln.get(source_key, [])
                if isinstance(source_list, list):
                    for item in source_list:
                        if isinstance(item, str) and item.startswith("CVE-"):
                            potential_cves.add(item)

            if len(potential_cves) == 1:
                # One-to-one mapping found
                mapped_cve = list(potential_cves)[0]
                if mapped_cve not in cve_data:
                    cve_data[mapped_cve] = {"osv_id": vuln_id, "osv_url": osv_url}
            else:
                # Zero or multiple CVEs: listed by OSV ID as "not CVE matching"
                if vuln_id not in cve_data:
                    cve_data[vuln_id] = {"osv_id": vuln_id, "osv_url": osv_url}
    else:
        # print(f"No vulnerabilities found in OSV for {purl}")
        pass

    elapsed_time = time.time() - start_time
    return cve_data, elapsed_time


def get_circl_data(cpe_string):
    start_time = time.time()
    url = f"{CIRCL_API_URL}/{cpe_string}"
    cve_data = {}
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        save_raw_json("circl", data)
    except requests.exceptions.Timeout:
        print(f"Request to {url} timed out.")
        return {}, time.time() - start_time
    except requests.exceptions.RequestException as e:
        print(f"Request to {url} failed: {e}")
        return {}, time.time() - start_time

    for source, vulns in data.items():
        if isinstance(vulns, list):
            for v in vulns:
                cve_id = v.get("cveMetadata", {}).get("cveId")
                if cve_id and cve_id.startswith("CVE-"):
                    if cve_id not in cve_data:
                        cve_data[cve_id] = (
                            f"https://vulnerability.circl.lu/vulnerability/{cve_id}"
                        )
        elif isinstance(vulns, dict):
            for k, v in vulns.items():
                cve_id = v.get("cveMetadata", {}).get("cveId", k)
                if cve_id and str(cve_id).startswith("CVE-"):
                    if cve_id not in cve_data:
                        cve_data[cve_id] = (
                            f"https://vulnerability.circl.lu/vulnerability/{cve_id}"
                        )

    elapsed_time = time.time() - start_time
    return cve_data, elapsed_time


# Get CVE data from all combinations of endpoints and parameter sets

# 2. NVD (CPE)
nvd_query_url = f"{NVD_API_URL}?{urlencode(params_nvd)}"
print(f"Querying NVD API: {nvd_query_url}...", end="", flush=True)
cve_nvd, time_nvd = get_nvd_data(NVD_API_URL, params_nvd)
print(" Done.")

# 3. CIRCL (CPE)
circl_query_url = f"{CIRCL_API_URL}/{cpe_value}"
print(f"Querying CIRCL API: {circl_query_url}...", end="", flush=True)
cve_circl, time_circl = get_circl_data(cpe_value)
print(" Done.")

# 4. OSV (PURL)
osv_payload = {"package": {"purl": purl_value}}
print(
    f"Querying OSV API: {OSV_API_URL} (Payload: {osv_payload})...", end="", flush=True
)
cve_osv, time_osv = get_osv_data(purl_value)
print(" Done.")


# Print Summary Results
print("\n--- Vulnerability Scan Summary ---")
print(f"Package (CPE): {cpe_value}")
print(f"Package (PURL): {purl_value}")
print("-" * 34)
print(f"NVD CVE API 2.0: {len(cve_nvd):3} CVEs found ({time_nvd:.2f}s)")
print(f"OSV API        : {len(cve_osv):3} CVEs found ({time_osv:.2f}s)")
print(f"CIRCL API      : {len(cve_circl):3} CVEs found ({time_circl:.2f}s)")
print("-" * 34)

# Prepare the table of vulnerability IDs
cve_sets = [
    set(cve_nvd.keys()),
    set(cve_osv.keys()),
    set(cve_circl.keys()),
]
all_vuln_ids = sorted(set().union(*cve_sets))

table_data = {
    "Vulnerability ID": [],
    "NVD 2.0": [],
    "OSV": [],
    "CIRCL": [],
    "Link": [],
}

for vuln_id in all_vuln_ids:
    display_id = vuln_id
    if not vuln_id.startswith("CVE-"):
        display_id = f"{vuln_id} (No CVE match)"
    table_data["Vulnerability ID"].append(display_id)

    table_data["NVD 2.0"].append("X" if vuln_id in cve_sets[0] else "")
    table_data["OSV"].append(cve_osv.get(vuln_id, {}).get("osv_id", ""))
    table_data["CIRCL"].append("X" if vuln_id in cve_sets[2] else "")

    # For the Link, prioritize NVD for CVEs, otherwise use documented source
    if vuln_id.startswith("CVE-"):
        url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    else:
        # Fallback to the link provided by OSV if it's a non-CVE ID
        url = cve_osv.get(vuln_id, {}).get(
            "osv_url", f"https://osv.dev/vulnerability/{vuln_id}"
        )
    table_data["Link"].append(url)

# Create a DataFrame and convert to a markdown table
df = pd.DataFrame(table_data)

# Print the table
print("\nCVE ID Comparison Table:")
try:
    print(df.to_markdown(index=False))
except ImportError:
    print(df.to_string(index=False))
