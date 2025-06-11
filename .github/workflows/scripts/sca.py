import sys
import json
import requests
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_vulnerability_details(vuln_id):
    try:
        res = requests.get(f"https://api.osv.dev/v1/vulns/{quote(vuln_id)}", timeout=10)
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        print(f"Error fetching details for {vuln_id}: {str(e)}", file=sys.stderr)
        return None

def check_package_vulnerabilities(pkg, version):
    try:
        res = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "version": version
            },
            timeout=15
        )
        res.raise_for_status()
        return pkg, version, res.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"Error checking {pkg}=={version}: {str(e)}", file=sys.stderr)
        return pkg, version, []
        
def read_requirements_file(file_path):
    encodings = ['utf-8', 'utf-16', 'latin-1']
    packages = []
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    if "==" in line:
                        pkg, version = line.split("==", 1)
                    elif ">=" in line:
                        pkg, version = line.split(">=", 1)
                    elif "<=" in line:
                        pkg, version = line.split("<=", 1)
                    elif "~=" in line:
                        pkg, version = line.split("~=", 1)
                    else:
                        continue
                    
                    packages.append((pkg.strip(), version.strip()))
            return packages
        except UnicodeDecodeError:
            continue
    
    raise ValueError(f"Could not read {file_path} with any of the supported encodings: {encodings}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python sca.py <requirements.txt> [--output=output.json]", file=sys.stderr)
        sys.exit(1)

    output_file = "sca_results.json"
    if len(sys.argv) > 2 and sys.argv[2].startswith("--output="):
        output_file = sys.argv[2].split("=")[1]

    try:
        packages = read_requirements_file(sys.argv[1])
    except Exception as e:
        print(f"Error reading requirements file: {str(e)}", file=sys.stderr)
        sys.exit(1)

    def check_package_vulnerabilities(pkg, version):
    try:
        res = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "version": version
            },
            timeout=15
        )
        res.raise_for_status()
        return pkg, version, res.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"Error checking {pkg}=={version}: {str(e)}", file=sys.stderr)
        return pkg, version, []

# ... (بقية الدوال تبقى كما هي)

def main():
    # ... (الجزء الأول من main يبقى كما هو)
    
    vulns = []
    
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
                
                # معالجة severity بشكل آمن
                severity_score = 0
                if "severity" in v and v["severity"]:
                    if isinstance(v["severity"], list) and len(v["severity"]) > 0:
                        if isinstance(v["severity"][0], dict) and "score" in v["severity"][0]:
                            severity_score = float(v["severity"][0]["score"])
                        elif isinstance(v["severity"][0], (int, float)):
                            severity_score = float(v["severity"][0])
                    elif isinstance(v["severity"], (int, float, str)):
                        try:
                            severity_score = float(v["severity"])
                        except (ValueError, TypeError):
                            severity_score = 0
                
                vuln_info = {
                    "package": pkg,
                    "version": version,
                    "id": v["id"],
                    "cves": cves,
                    "summary": v.get("summary", ""),
                    "severity": severity_score,  # الآن ستكون رقمياً دائماً
                    "details": v.get("details", ""),
                    "references": v.get("references", []),
                    "published_date": v.get("published", ""),
                    "modified_date": v.get("modified", ""),
                    "affected_versions": vuln_details.get("affected", []) if vuln_details else []
                }
                vulns.append(vuln_info)

    if vulns:
        # الترتيب الآن سيعمل بدون أخطاء
        vulns.sort(key=lambda x: (
            -len(x["cves"]),
            -x["severity"]
        ))

        # ... (بقية الدالة تبقى كما هي)

        try:
            with open(output_file, "w", encoding="utf-8") as out:
                json.dump({
                    "metadata": {
                        "source": "OSV Database",
                        "scanned_file": sys.argv[1],
                        "total_packages_scanned": len(packages),
                        "total_vulnerabilities": len(vulns),
                        "unique_cves": len({cve for vuln in vulns for cve in vuln["cves"]}),
                        "highest_severity": max(vuln["severity"] for vuln in vulns) if vulns else 0
                    },
                    "vulnerabilities": vulns
                }, out, indent=2, ensure_ascii=False)

            print(f"Found {len(vulns)} vulnerabilities across {len(packages)} packages. Results saved to {output_file}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error writing output file: {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"No known vulnerabilities found in {len(packages)} packages.", file=sys.stderr)
        sys.exit(0)

if __name__ == "__main__":
    main()
