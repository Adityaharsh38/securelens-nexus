
import argparse
import json
from pathlib import Path

from rules.sql_injection import analyze_sql_injection


def analyze_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {path}")

    if path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs"}:
        raise ValueError("The first analyzer version supports JavaScript files only.")

    source = path.read_text(encoding="utf-8")
    findings = analyze_sql_injection(source)

    return {
        "file": path.name,
        "language": "javascript",
        "findingsCount": len(findings),
        "findings": findings,
        "analysis": "heuristic",
        "limitation": (
            "Pattern-based analysis only. Results require review; "
            "absence of findings does not prove code is safe."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="SecureLens source analyzer")
    parser.add_argument("--file", required=True, help="JavaScript source file")
    args = parser.parse_args()

    try:
        print(json.dumps(analyze_file(args.file), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
