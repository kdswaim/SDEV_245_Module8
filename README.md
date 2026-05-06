# Secret Scanner

A CLI tool that scans files and directories for hardcoded secrets like API keys, passwords, and tokens.

---

## Detection Logic

The tool reads through every line of every file in the target path and checks each line against a list of regex patterns. Each pattern is designed to match the format of a real secret. If a match is found, it records the filename, line number, and matched string. Binary files are skipped automatically.

Patterns are sourced from [regextokens by odomojuli](https://github.com/odomojuli/regextokens) and include: AWS Access Keys, Google API Keys, GitHub Tokens, Slack Tokens, Stripe API Keys, OpenAI API Keys, Twilio Tokens, MailChimp Tokens, hardcoded passwords, and private key headers, among others.

---

## Usage

**Scan a file:**
```bash
python scanner.py myfile.py
```

**Scan a directory:**
```bash
python scanner.py ./my_project
```

**Save output to a file:**
```bash
python scanner.py ./my_project --output report.txt
```

**Verbose logging:**
```bash
python scanner.py ./my_project --verbose
```

**List all patterns:**
```bash
python scanner.py . --list-patterns
```

### Final Note
Thank you for the class! It definitely made learning security a lot less intimidating and complicated to me. Have a wonderful summer! ☺️🔆