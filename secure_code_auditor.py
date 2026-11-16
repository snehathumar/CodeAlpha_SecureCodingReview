#!/usr/bin/env python3
"""
Standalone Secure Coding Audit CLI (plain Python 3, zero external dependencies).
Scans a single file or directory recursively using Python ast.parse for .py files
and deterministic security regex rules for JS/TS/PHP/Go/SQL files.

Usage:
  python3 secure_code_auditor.py <path> [--report AUDIT_REPORT.md]
"""
import argparse
import datetime
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent
SERVER_DIR = REPO_ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from python_ast_auditor import audit_python_source  # noqa: E402

SKIP_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "__pycache__",
    "venv",
    ".venv",
    ".playwright-cli",
    "data",
}

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".go": "go",
    ".sql": "sql",
}

REGEX_RULES: List[Dict[str, Any]] = [
    {
        "ruleId": "SAST-JS-001",
        "ruleName": "SQL Injection via Template Interpolation / Concatenation",
        "languages": {"javascript", "typescript"},
        "cweId": "CWE-89",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.8,
        "pattern": re.compile(r"(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)", re.I),
        "recommendation": "Use parameterized SQL queries with bound placeholder arguments.",
        "secure": 'await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);',
    },
    {
        "ruleId": "SAST-JS-002",
        "ruleName": "OS Command Injection via Child Process Shell",
        "languages": {"javascript", "typescript"},
        "cweId": "CWE-78",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.8,
        "pattern": re.compile(r"(?:child_process\.)?(?:exec|execSync)\s*\("),
        "recommendation": "Use execFile() or spawn() with an argument array and shell: false.",
        "secure": 'execFile("ping", ["-c", "1", safeHost], { shell: false });',
    },
    {
        "ruleId": "SAST-JS-009",
        "ruleName": "Dynamic Code Execution (eval / new Function)",
        "languages": {"javascript", "typescript"},
        "cweId": "CWE-95",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.0,
        "pattern": re.compile(r"(?:^|[^.\w])(?:eval\s*\(|new\s+Function\s*\()"),
        "recommendation": "Replace dynamic evaluation with JSON.parse or safe declarative lookups.",
        "secure": "const value = JSON.parse(rawPayload);",
    },
    {
        "ruleId": "SAST-JS-005",
        "ruleName": "Cross-Site Scripting (Unsafe DOM Sink)",
        "languages": {"javascript", "typescript"},
        "cweId": "CWE-79",
        "owaspCategory": "A03:2021 Injection",
        "severity": "high",
        "cvssScore": 7.5,
        "pattern": re.compile(r"(?:dangerouslySetInnerHTML\s*=\s*\{|\.innerHTML\s*=|document\.write\s*\()"),
        "recommendation": "Use textContent or sanitize untrusted HTML with DOMPurify.",
        "secure": "element.textContent = untrustedText;",
    },
    {
        "ruleId": "SAST-PHP-001",
        "ruleName": "PHP SQL Injection via String Concatenation",
        "languages": {"php"},
        "cweId": "CWE-89",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.8,
        "pattern": re.compile(r"(?:mysqli_query|mysql_query|pg_query|->query|->exec)\s*\([^)]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|[\"']\s*\.\s*\$|SELECT[^\"']*\$[a-zA-Z_])", re.I),
        "recommendation": "Use PDO or mysqli prepared statements with parameter binding.",
        "secure": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
    },
    {
        "ruleId": "SAST-PHP-002",
        "ruleName": "PHP OS Command Injection (shell_exec / exec / system)",
        "languages": {"php"},
        "cweId": "CWE-78",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.8,
        "pattern": re.compile(r"(?:^|[^a-zA-Z0-9_])(?:shell_exec|exec|system|passthru|proc_open)\s*\("),
        "recommendation": "Avoid shell calls; validate inputs against an allowlist and escape with escapeshellarg().",
        "secure": '$out = shell_exec("ping -c 1 " . escapeshellarg($validatedHost));',
    },
    {
        "ruleId": "SAST-PHP-003",
        "ruleName": "PHP Dynamic Code Execution (eval)",
        "languages": {"php"},
        "cweId": "CWE-95",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.0,
        "pattern": re.compile(r"(?:^|[^a-zA-Z0-9_])eval\s*\("),
        "recommendation": "Remove eval() and parse structured data via json_decode().",
        "secure": "$data = json_decode($_POST['payload'], true, 512, JSON_THROW_ON_ERROR);",
    },
    {
        "ruleId": "SAST-PHP-004",
        "ruleName": "PHP Hardcoded Secret or Credential",
        "languages": {"php"},
        "cweId": "CWE-798",
        "owaspCategory": "A07:2021 Identification and Authentication Failures",
        "severity": "critical",
        "cvssScore": 9.1,
        "pattern": re.compile(r"(?:\$(?:api_?key|secret_?key|jwt_?secret|db_?pass(?:word)?|password|private_?key|access_?token)\s*=\s*[\"'][^\"'\s]{6,}[\"'])", re.I),
        "recommendation": "Load credentials via getenv() or a secrets manager.",
        "secure": '$db_password = getenv("DB_PASSWORD");',
    },
    {
        "ruleId": "SAST-PHP-005",
        "ruleName": "PHP Path Traversal (include / require with User Input)",
        "languages": {"php"},
        "cweId": "CWE-22",
        "owaspCategory": "A01:2021 Broken Access Control",
        "severity": "high",
        "cvssScore": 8.2,
        "pattern": re.compile(r"(?:include|include_once|require|require_once)\s*(?:\(\s*)?[^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$[a-zA-Z_][a-zA-Z0-9_]*)", re.I),
        "recommendation": "Validate requested file keys against an explicit template allowlist.",
        "secure": "$allowed = ['home' => 'pages/home.php']; include($allowed[$page] ?? 'pages/home.php');",
    },
    {
        "ruleId": "SAST-GO-001",
        "ruleName": "Go SQL Query String Formatting",
        "languages": {"go"},
        "cweId": "CWE-89",
        "owaspCategory": "A03:2021 Injection",
        "severity": "critical",
        "cvssScore": 9.6,
        "pattern": re.compile(r"(?:Query|QueryRow|Exec)\s*\(\s*(?:fmt\.Sprintf\(|\"[^\"]*\"\s*\+)"),
        "recommendation": "Pass parameterized arguments ($1 / ?) to QueryContext / ExecContext.",
        "secure": 'db.QueryRowContext(ctx, "SELECT id FROM accounts WHERE user = $1", username)',
    },
    {
        "ruleId": "SAST-ALL-003",
        "ruleName": "Hardcoded Secret or Credential",
        "languages": {"javascript", "typescript", "go", "sql"},
        "cweId": "CWE-798",
        "owaspCategory": "A07:2021 Identification and Authentication Failures",
        "severity": "critical",
        "cvssScore": 9.1,
        "pattern": re.compile(r"(?:API_KEY|SECRET_KEY|JWT_SECRET|DB_PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|ADMIN_SECRET)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']", re.I),
        "recommendation": "Inject secrets dynamically via environment variables or Secret Manager.",
        "secure": "const secret = process.env.SERVICE_SECRET;",
    },
]


def scan_non_python_file(file_path: Path, rel_path: str, language: str) -> List[Dict[str, Any]]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    findings: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("--"):
            continue
        if language == "php" and trimmed.startswith("#"):
            continue

        for rule in REGEX_RULES:
            if language not in rule["languages"]:
                continue
            if rule["pattern"].search(line):
                findings.append(
                    {
                        "filePath": rel_path,
                        "language": language,
                        "engine": "Regex",
                        "ruleId": rule["ruleId"],
                        "ruleName": rule["ruleName"],
                        "line": idx + 1,
                        "severity": rule["severity"],
                        "cvssScore": rule["cvssScore"],
                        "cweId": rule["cweId"],
                        "owaspCategory": rule["owaspCategory"],
                        "codeLine": trimmed,
                        "recommendation": rule["recommendation"],
                        "remediationExample": {
                            "vulnerable": trimmed,
                            "secure": rule["secure"],
                        },
                    }
                )
    return findings


def scan_path(target_path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if target_path.is_file():
        files_to_scan = [target_path]
        base_root = target_path.parent
    else:
        base_root = target_path
        files_to_scan = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in sorted(dirs) if d not in SKIP_DIRS]
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_to_scan.append(fpath)

    for fpath in files_to_scan:
        ext = fpath.suffix.lower()
        language = SUPPORTED_EXTENSIONS.get(ext)
        if not language:
            continue
        try:
            rel_path = str(fpath.relative_to(base_root))
        except ValueError:
            rel_path = fpath.name

        if language == "python":
            source = fpath.read_text(encoding="utf-8", errors="replace")
            ast_res = audit_python_source(source)
            for item in ast_res.get("findings", []):
                findings.append(
                    {
                        "filePath": rel_path,
                        "language": "python",
                        "engine": "AST",
                        "ruleId": item["ruleId"],
                        "ruleName": item["ruleName"],
                        "line": item["line"],
                        "severity": item["severity"],
                        "cvssScore": item["cvssScore"],
                        "cweId": item["cweId"],
                        "owaspCategory": item["owaspCategory"],
                        "codeLine": item["codeLine"],
                        "recommendation": item["recommendation"],
                        "remediationExample": item["remediationExample"],
                    }
                )
        else:
            findings.extend(scan_non_python_file(fpath, rel_path, language))

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(
        key=lambda f: (-sev_rank.get(f["severity"], 0), f["filePath"], f["line"])
    )
    return findings


def render_markdown_report(target_label: str, findings: List[Dict[str, Any]]) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    today = datetime.date.today().isoformat()
    lines: List[str] = [
        f"# Secure Coding Audit Report: `{target_label}`",
        "",
        f"- **Generated:** {today}",
        "- **Tool:** `secure_code_auditor.py` (Aegis Code Audit Standalone CLI — Python `ast.parse` + Regex Rules)",
        f"- **Total Findings:** {len(findings)}",
        "",
        "## Summary Table",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| **Total** | **{len(findings)}** |",
        "",
        "## Detailed Findings",
        "",
    ]

    if not findings:
        lines.append("No vulnerabilities detected.")
        lines.append("")
    else:
        for idx, f in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {idx}. [{f['severity'].upper()}] {f['ruleName']}",
                    "",
                    f"- **File & Line:** `{f['filePath']}:{f['line']}`",
                    f"- **Engine:** {f['engine']}",
                    f"- **CWE:** {f['cweId']}",
                    f"- **OWASP Category:** {f['owaspCategory']}",
                    f"- **Recommendation:** {f['recommendation']}",
                    "",
                    "**Vulnerable Code:**",
                    "```python" if f["language"] == "python" else "```",
                    f["codeLine"],
                    "```",
                    "",
                    "**Secure Fix Code:**",
                    "```python" if f["language"] == "python" else "```",
                    f["remediationExample"]["secure"],
                    "```",
                    "",
                ]
            )

    lines.extend(
        [
            "## Secure coding recommendations",
            "",
            "1. **Eliminate hardcoded secrets:** Load database credentials, API keys, and signing tokens from environment variables or Google Cloud Secret Manager (`os.environ`).",
            "2. **Use parameterized database queries:** Always pass bound parameter tuples/arrays (`%s`, `?`, `$1`) instead of string concatenation or f-strings.",
            "3. **Avoid shell execution and dynamic code evaluation:** Replace `os.system()` / `shell=True` with `subprocess.run([...], shell=False)`, and replace `eval()` with `ast.literal_eval()` or `json.loads()`.",
            "4. **Upgrade legacy cryptography:** Replace MD5/SHA-1 with Argon2id or `bcrypt` for password hashing, and SHA-256/HMAC-SHA256 for data integrity.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone Secure Coding Audit CLI (AST + Regex SAST)"
    )
    parser.add_argument("target", help="Path to source file or directory to scan")
    parser.add_argument(
        "--report",
        dest="report_path",
        help="Optional Markdown report output path (e.g., AUDIT_REPORT.md)",
    )
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    findings = scan_path(target_path)

    print(f"Aegis Standalone Audit — Target: {args.target}")
    print(f"Findings detected: {len(findings)}")
    print("-" * 72)
    for idx, f in enumerate(findings, start=1):
        print(
            f"[{idx}] {f['severity'].upper()} | {f['cweId']} | {f['engine']} | "
            f"{f['filePath']}:{f['line']} — {f['ruleName']}"
        )
        print(f"    Code: {f['codeLine']}")
        print(f"    Fix:  {f['recommendation']}")
        print()

    if args.report_path:
        report_md = render_markdown_report(args.target, findings)
        Path(args.report_path).write_text(report_md, encoding="utf-8")
        print(f"Markdown report written to {args.report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
