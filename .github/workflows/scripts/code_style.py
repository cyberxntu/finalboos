import os
import sys
import json
issues = []

def load_ignore_list(file_path=".scannerignore"):
    ignore_list = set()
    if os.path.exists(file_path):
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ignore_list.add(line)
    return ignore_list

def should_ignore(filepath, ignore_list):
    return any(ignored in filepath for ignored in ignore_list)

ignore_list = load_ignore_list()
targets = sys.argv[1:] if len(sys.argv) > 1 else ["."]

for target in targets:
    if os.path.isfile(target) and target.endswith(".py"):
        if should_ignore(target, ignore_list):
            continue
        with open(target, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if len(line) > 100:
                    issues.append({
                        "file": target,
                        "line": i,
                        "issue": "Line exceeds 100 characters"
                    })
                if ";" in line:
                    issues.append({
                        "file": target,
                        "line": i,
                        "issue": "Unnecessary semicolon"
                    })

    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for file in files:
                if not file.endswith(".py"):
                    continue
                filepath = os.path.join(root, file)
                if should_ignore(filepath, ignore_list):
                    continue
                with open(filepath, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f, 1):
                        if len(line) > 100:
                            issues.append({
                                "file": filepath,
                                "line": i,
                                "issue": "Line exceeds 100 characters"
                            })
                        if ";" in line:
                            issues.append({
                                "file": filepath,
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
