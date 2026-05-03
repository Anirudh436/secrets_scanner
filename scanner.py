import os
import re
import sys
import json
from patterns import PATTERNS
from entropy import shannon_entropy


def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()

        for i, line in enumerate(lines, start=1):

            # Pattern matching
            for name, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": name,
                        "severity": "HIGH"
                    })

            # Entropy detection
            tokens = re.findall(r"[A-Za-z0-9_\-]{20,}", line)
            for token in tokens:
                if shannon_entropy(token) > 4.5:
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "HIGH_ENTROPY_STRING",
                        "severity": "MEDIUM"
                    })

    except Exception:
        pass

    return findings


def scan_directory(path):
    all_findings = []

    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith((".py", ".js", ".env", ".txt")):
                file_path = os.path.join(root, file)
                file_findings = scan_file(file_path)
                all_findings.extend(file_findings)

    return all_findings


def deduplicate_findings(findings):
    seen = set()
    unique = []

    for f in findings:
        key = (f["file"], f["line"], f["type"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def build_summary(findings):
    summary = {
        "total": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for f in findings:
        severity = f.get("severity", "LOW").lower()

        if severity == "high":
            summary["high"] += 1
        elif severity == "medium":
            summary["medium"] += 1
        else:
            summary["low"] += 1

    return summary


def main():
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = os.environ.get("OUTPUT_FILE", "output.json")

    findings = scan_directory(repo_path)
    findings = deduplicate_findings(findings)
    summary = build_summary(findings)

    result = {
        "tool": "secrets_scanner",
        "summary": summary,
        "data": findings
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=4)

    print(f"[✔] Scan complete. Findings: {summary['total']}")


if __name__ == "__main__":
    main()
