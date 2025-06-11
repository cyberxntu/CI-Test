import os
import sys
import json
issues = []

for root, _, files in os.walk("."):
    for file in files:
        if file.endswith(".py"):
            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    if len(line) > 100:
                        issues.append({
                            "file": file,
                            "line": i,
                            "issue": "Line exceeds 100 characters"
                        })
                    if ";" in line:
                        issues.append({
                            "file": file,
                            "line": i,
                            "issue": "Unnecessary semicolon"
                        })

if issues:
    with open("style_results.json", "w") as out:
        json.dump(issues, out, indent=2)
    print("Code style issues found:")
    for issue in issues:
        print(issue)
    sys.exit(1)
else:
    print("Code style is clean.")
    sys.exit(0)
