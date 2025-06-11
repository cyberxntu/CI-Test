import sys
import json
import requests
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_vulnerability_details(vuln_id):
    try:
        res = requests.get(f"https://api.osv.dev/v1/vulns/{quote(vuln_id)}")
        res.raise_for_status()
        return res.json()
    except requests.RequestException:
        return None

def check_package_vulnerabilities(pkg, version):
    try:
        res = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "version": version
            },
            timeout=10
        )
        res.raise_for_status()
        return pkg, version, res.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"Error checking {pkg}=={version}: {str(e)}", file=sys.stderr)
        return pkg, version, []

def main():
    if len(sys.argv) < 2:
        print("Usage: python sca.py <requirements.txt> [--output=output.json]", file=sys.stderr)
        sys.exit(1)

    output_file = "sca_results.json"
    if len(sys.argv) > 2 and sys.argv[2].startswith("--output="):
        output_file = sys.argv[2].split("=")[1]

    vulns = []
    packages = []

    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "==" in line:
                pkg, version = line.split("==")
            elif ">=" in line:
                pkg, version = line.split(">=")
            elif "<=" in line:
                pkg, version = line.split("<=")
            elif "~=" in line:
                pkg, version = line.split("~=")
            else:
                continue
            
            packages.append((pkg.strip(), version.strip()))

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(check_package_vulnerabilities, pkg, version) 
                 for pkg, version in packages]
        
        for future in as_completed(futures):
            pkg, version, results = future.result()
            for v in results:
                vuln_details = get_vulnerability_details(v["id"])
                
                cves = []
                if "aliases" in v:
                    cves = [alias for alias in v["aliases"] if alias.startswith("CVE-")]
                elif vuln_details and "aliases" in vuln_details:
                    cves = [alias for alias in vuln_details["aliases"] if alias.startswith("CVE-")]
                
                vuln_info = {
                    "package": pkg,
                    "version": version,
                    "id": v["id"],
                    "cves": cves,
                    "summary": v.get("summary", ""),
                    "severity": v.get("severity", []),
                    "details": v.get("details", ""),
                    "references": v.get("references", []),
                    "published_date": v.get("published", ""),
                    "modified_date": v.get("modified", ""),
                    "affected_versions": vuln_details.get("affected", []) if vuln_details else []
                }
                vulns.append(vuln_info)

    if vulns:
        vulns.sort(key=lambda x: (
            -len(x["cves"]),
            x["severity"][0]["score"] if x.get("severity") else 0
        ))

        with open(output_file, "w", encoding="utf-8") as out:
            json.dump({
                "metadata": {
                    "source": "OSV Database",
                    "scanned_file": sys.argv[1],
                    "total_vulnerabilities": len(vulns),
                    "unique_cves": len({cve for vuln in vulns for cve in vuln["cves"]})
                },
                "vulnerabilities": vulns
            }, out, indent=2, ensure_ascii=False)

        print(f"Found {len(vulns)} vulnerabilities. Results saved to {output_file}", file=sys.stderr)
        sys.exit(1)
    else:
        print("No known vulnerabilities in dependencies.", file=sys.stderr)
        sys.exit(0)

if __name__ == "__main__":
    main()
