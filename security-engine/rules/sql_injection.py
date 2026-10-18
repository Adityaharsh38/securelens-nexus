
import re


RULE_ID = "JS-SQLI-001"

SQL_KEYWORDS = r"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)"


def analyze_sql_injection(source: str) -> list[dict]:
    findings = []
    lines = source.splitlines()

    # Find variables assigned SQL template literals with interpolation.
    interpolated_variables = set()

    assignment_pattern = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*`([^`]*\$\{[^}]+\}[^`]*)`""",
        re.DOTALL,
    )

    for match in assignment_pattern.finditer(source):
        variable, template = match.groups()

        if re.search(SQL_KEYWORDS, template, re.IGNORECASE):
            interpolated_variables.add(variable)

            line_number = source.count("\n", 0, match.start()) + 1
            query_usage = re.search(
                rf"\b(?:query|execute|raw)\s*\(\s*{re.escape(variable)}\s*\)",
                source,
            )

            if query_usage:
                findings.append({
                    "ruleId": RULE_ID,
                    "type": "SQL_INJECTION",
                    "severity": "high",
                    "line": line_number,
                    "message": (
                        "Possible SQL injection: an interpolated SQL "
                        "template is passed to a database execution method."
                    ),
                    "evidence": lines[line_number - 1].strip(),
                    "recommendation": (
                        "Use parameterized queries and pass user-controlled "
                        "values separately from the SQL statement."
                    ),
                    "confidence": "heuristic",
                })

    # Find direct interpolated SQL passed to query/execute/raw.
    direct_pattern = re.compile(
        r"""\b(?:query|execute|raw)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`""",
        re.IGNORECASE | re.DOTALL,
    )

    for match in direct_pattern.finditer(source):
        template = match.group(1)

        if re.search(SQL_KEYWORDS, template, re.IGNORECASE):
            line_number = source.count("\n", 0, match.start()) + 1

            findings.append({
                "ruleId": RULE_ID,
                "type": "SQL_INJECTION",
                "severity": "high",
                "line": line_number,
                "message": "Possible SQL injection through direct template interpolation.",
                "evidence": lines[line_number - 1].strip(),
                "recommendation": (
                    "Use parameterized queries and pass input values separately."
                ),
                "confidence": "heuristic",
            })

    return findings
