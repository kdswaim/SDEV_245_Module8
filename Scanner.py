import argparse
import logging
import os
import re
import sys

SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "GitHub Personal Access Token (Classic)": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub Fine-Grained Token": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
    "GitHub OAuth Token": r"gho_[a-zA-Z0-9]{36}",
    "Slack Bot Token": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
    "Slack User Token": r"xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
    "Slack Webhook": r"T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24,}",
    "Mailgun Access Token": r"key-[0-9a-zA-Z]{32}",
    "MailChimp Access Token": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Twilio Access Token": r"55[0-9a-fA-F]{32}",
    "Square Access Token": r"sqOatp-[0-9A-Za-z\-_]{22}",
    "Twitter Access Token": r"[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "OpenAI Project Key": r"sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "WakaTime API Key": r"waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Generic Password in Code": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
    "Generic API Key Assignment": r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][^'\"]{8,}['\"]",
    "Generic Secret Assignment": r"(?i)(secret|secret_key)\s*=\s*['\"][^'\"]{8,}['\"]",
    "Private Key Header": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin", ".lock",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def scan_file(filepath):
    findings = []
    _, ext = os.path.splitext(filepath)
    if ext.lower() in SKIP_EXTENSIONS:
        logger.debug(f"Skipping binary/non-text file: {filepath}")
        return findings

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, PermissionError) as e:
        logger.warning(f"Could not read file {filepath}: {e}")
        return findings

    for line_number, line in enumerate(lines, start=1):
        for pattern_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, line)
            for match in matches:
                if isinstance(match, tuple):
                    match = " ".join(m for m in match if m)
                finding = {
                    "file": filepath,
                    "line": line_number,
                    "pattern": pattern_name,
                    "match": match.strip(),
                }
                findings.append(finding)
                logger.debug(f"Found: {pattern_name} in {filepath}:{line_number}")

    return findings


def scan_path(target_path):
    all_findings = []

    if os.path.isfile(target_path):
        logger.info(f"Scanning file: {target_path}")
        all_findings.extend(scan_file(target_path))
    elif os.path.isdir(target_path):
        logger.info(f"Scanning directory: {target_path}")
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__", ".git")]
            for filename in files:
                full_path = os.path.join(root, filename)
                logger.info(f"Scanning: {full_path}")
                all_findings.extend(scan_file(full_path))
    else:
        logger.error(f"Path does not exist: {target_path}")
        sys.exit(1)

    return all_findings


def print_report(findings, output_file=None):
    lines = []
    lines.append("=" * 70)
    lines.append("SECRET SCANNER REPORT")
    lines.append("=" * 70)

    if not findings:
        lines.append("\nNo secrets found. Your code looks clean!")
    else:
        lines.append(f"\nTotal findings: {len(findings)}\n")
        lines.append("-" * 70)

        grouped = {}
        for f in findings:
            key = f["file"]
            grouped.setdefault(key, []).append(f)

        for filepath, file_findings in grouped.items():
            lines.append(f"\nFile: {filepath}")
            lines.append(f"  Findings: {len(file_findings)}")
            for f in file_findings:
                lines.append(f"  Line {f['line']:>5}  |  {f['pattern']}")
                lines.append(f"            Match: {f['match'][:80]}")
            lines.append("-" * 70)

    lines.append("\nScan complete.")
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    print(report_text)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            logger.info(f"Report saved to: {output_file}")
        except OSError as e:
            logger.error(f"Could not write report to {output_file}: {e}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan files or directories for hardcoded secrets like API keys, tokens, and passwords.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py myfile.py
  python scanner.py ./my_project
  python scanner.py ./my_project --output report.txt
  python scanner.py ./my_project --verbose
        """,
    )
    parser.add_argument(
        "target",
        help="Path to the file or directory you want to scan.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save the report to this file in addition to printing it.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed logging while scanning.",
    )
    parser.add_argument(
        "--list-patterns",
        action="store_true",
        help="Print all the secret patterns being checked, then exit.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_patterns:
        print("\nPatterns currently being scanned for:\n")
        for name in SECRET_PATTERNS:
            print(f"  - {name}")
        print()
        sys.exit(0)

    findings = scan_path(args.target)
    print_report(findings, output_file=args.output)

    if findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()