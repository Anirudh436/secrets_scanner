import os
import re
import sys
import json
from patterns import PATTERNS
from entropy import shannon_entropy

RESULTS = []

def scan_file(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()

        for i, line in enumerate(lines, start=1):

            # Pattern matching
            for name, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    RESULTS.append({
                        "file": file_path,
                        "line": i,
                        "type": name,
                        "severity": "HIGH"
                    })

            # Entropy detection
            tokens = re.findall(r"[A-Za-z0-9_\-]{20,}", line)
            for token in tokens:
                if shannon_entropy(token) > 4.5:
                    RESULTS.append({
                        "file": file_path,
                        "line": i,
                        "type": "HIGH_ENTROPY_STRING",
                        "severity": "MEDIUM"
                    })

    except Exception:
        pass


def scan_directory(path):
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith((".py", ".js", ".env", ".txt")):
                scan_file(os.path.join(root, file))


def main():
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = os.environ.get("OUTPUT_FILE", "output.json")

    scan_directory(repo_path)

    with open(output_path, "w") as f:
        json.dump(RESULTS, f, indent=4)

if __name__ == "__main__":
    main()