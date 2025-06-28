import sys
import os
import json
import requests
import glob

def load_ignore_list(path=".scannerignore"):
    ignore_list = set()
    if os.path.exists(path):
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ignore_list.add(line)
            except Exception as e:
                print(f"[!] Failed to read file: {path} -- {e}")
        elif os.path.isdir(path):
            files = glob.glob(os.path.join(path, "*"))
            for file_path in files:
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    ignore_list.add(line)
                    except Exception as e:
                        print(f"[!] Skipping file due to read error: {file_path} -- {e}")
    return ignore_list

def should_ignore(filepath, ignore_list):
    filename = os.path.basename(filepath)
    normalized_path = os.path.normpath(filepath)

    for ignored in ignore_list:
        ignored = ignored.strip()
        if not ignored:
            continue
        ignored_path = os.path.normpath(ignored)

        # تطابق دقيق لمسار الملف بالكامل
        if normalized_path == ignored_path:
            return True
        # تطابق دقيق باسم الملف فقط
        if filename == ignored:
            return True
    return False

def analyze_requirements(filepath):
    vulns = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or '==' not in line:
                continue
            pkg, version = line.split("==")
            try:
                res = requests.post("https://api.osv.dev/v1/query", json={
                    "package": {"name": pkg, "ecosystem": "PyPI"},
                    "version": version
                })
                res.raise_for_status()
                results = res.json().get("vulns", [])
                for v in results:
                    vulns.append({
                        "file": filepath,
                        "package": pkg,
                        "version": version,
                        "id": v["id"],
                        "summary": v.get("summary", "")
                    })
            except Exception as e:
                print(f"[!] Failed to query OSV for {pkg}=={version}: {e}")
    return vulns

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python sca.py <requirements.txt> [additional_files...]")
        sys.exit(1)

    ignore_list = load_ignore_list()
    print(f"[DEBUG] Loaded ignore list: {ignore_list}")

    results = []
    targets = sys.argv[1:]

    for target in targets:
        if should_ignore(target, ignore_list):
            print(f"[i] Ignored {target} based on ignore list")
            continue
        if os.path.isfile(target) and target.endswith("requirements.txt"):
            results.extend(analyze_requirements(target))

    if results:
        with open("sca_results.json", "w", encoding="utf-8") as out:
            json.dump(results, out, indent=2)
        print(json.dumps(results, indent=2))
        sys.exit(1)
    else:
        print("No known vulnerabilities in dependencies.")
        sys.exit(0)
