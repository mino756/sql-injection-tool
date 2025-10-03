# sql-injection-tool v 2.0.1

A lightweight Python tool for testing SQL Injection vulnerabilities.

> ⚠️ **Legal & Responsible Use Notice**
>
> This tool is intended **ONLY** for security testing on systems you own or have explicit, written permission to test. Unauthorized scanning, testing or exploitation of systems you do not own is illegal and unethical. The project owner and contributors are NOT responsible for misuse. See `SECURITY.md` for responsible disclosure instructions.

---

## Contents

* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Quick Examples](#quick-examples)
* [Recommended CLI Options](#recommended-cli-options)
* [Output Format](#output-format)
* [Security & Responsible Testing](#security--responsible-testing)
* [Contributing](#contributing)
* [License](#license)
* [Changelog](#changelog)
* [FAQ](#faq)
* [Contact](#contact)

---

## Features

* Scan GET/POST parameters for common SQL injection indicators.
* Heuristics for DBMS fingerprinting (e.g. MySQL, PostgreSQL, MSSQL) based on error strings and responses.
* Menu-based interactive mode and a scriptable CLI via `argparse`.
* Option to automatically run a suite of tests when a URL is provided (`--auto-run`).
* Save results to JSON for later analysis.

> WARNING: Advanced features such as OOB (out-of-band) detection or WAF bypass techniques may trigger network callbacks. Use them only in controlled test environments.

## Requirements

* Python 3.10+ recommended.

Suggested `requirements.txt` example:

```
requests>=2.28
beautifulsoup4>=4.12
charset-normalizer>=2.1
urllib3>=1.26
```

Add any other libraries your code actually uses.

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/mino756/sql-injection-tool.git
cd sql-injection-tool

# create and activate a virtualenv (recommended)
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows
venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

Default script filename in this repo: `sql-injection-tool.py` (adjust if you rename the file).

Show help:

```bash
python sql-injection-tool.py --help
```

Basic GET parameter scan:

```bash
python sql-injection-tool.py -u "http://example.com/search?q=test" -p q --output results.json
```

Interactive menu mode:

```bash
python sql-injection-tool.py --interactive
```

Run with OOB/network callbacks disabled (safe default):

```bash
python sql-injection-tool.py -u "http://example.com/search?q=test" -p q --no-oob
```

## Quick Examples

1. Scan a local test application and save JSON results:

```bash
python sql-injection-tool.py -u "http://localhost:8080/vuln?id=1" -p id --output out.json
```

2. Test a POST form (example):

```bash
python sql-injection-tool.py -u "http://localhost/login" -X POST -d "username=admin&password=pass" -p username
```

> Use deliberately vulnerable labs (DVWA, OWASP Juice Shop, WebGoat) for testing.

## Recommended CLI options (for README reference)

* `-u, --url` : Target URL
* `-p, --param` : Parameter name to test
* `-X, --method` : HTTP method (GET or POST)
* `-d, --data` : POST data (when using POST)
* `--interactive` : Run menu-based interactive interface
* `--auto-run` : Execute all configured tests automatically on provided URL
* `--no-oob` : Disable any OOB/callback tests
* `--output` : Output file (JSON)
* `--verbose` : Verbose logging

## Output format

Store results in JSON with standardized fields. Example structure:

```json
{
  "url": "http://example.com/search?q=test",
  "param": "q",
  "vulnerable": true,
  "evidence": "Payload returned SQL error: ...",
  "dbms_guess": "MySQL",
  "timestamp": "2025-10-03T14:00:00Z"
}
```

Adjust fields to match what your code actually produces.

## Security & Responsible Testing

* Only test systems you own or have written permission to test.
* Prefer isolated test environments (VMs, local containers, intentionally vulnerable apps).
* Default to `--no-oob` to avoid outbound network callbacks unless you intentionally enable them.
* Do **not** store or publish sensitive data you may find during testing; follow a responsible disclosure process.
* Add `SECURITY.md` to the repo describing how to report vulnerabilities responsibly.

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repository.
2. Create a feature branch and write tests for new logic.
3. Run linting and tests locally (add a simple GitHub Actions CI to run these).
4. Open a Pull Request describing your changes.

Suggested CI: GitHub Actions that runs `ruff`/`flake8` and `pytest` on push/PR.

## License

This project is licensed under the **MIT License**. Include a `LICENSE` file in the repo.

## Changelog

* `v1.0.0` - Initial release: basic scanner, interactive mode, JSON output, README.

## FAQ

**Q: Does this tool exploit systems?**
A: The tool aims to detect indicators of SQL injection and produce evidence. Actual exploitation is not the intended default behavior; any exploit-like actions should only run in controlled environments.

**Q: Can I test production sites?**
A: No — never test production or third-party sites without explicit written permission.

## Contact

If you find a bug or a security issue, open an issue on GitHub or contact:

* Email: [your-email@example.com](mailto:your-email@example.com)  (replace with a real contact address)
* Issues: [https://github.com/mino756/sql-injection-tool/issues](https://github.com/mino756/sql-injection-tool/issues)

---

*Thank you for keeping security testing responsible and legal.*
