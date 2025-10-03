# sql-injection-tool v2.0.1

A lightweight Python tool for testing SQL Injection vulnerabilities.

> ⚠️ **Legal & Responsible Use Notice**
>
> This tool is intended **ONLY** for security testing on systems you own or have explicit, written permission to test. Unauthorized scanning, testing or exploitation of systems you do not own is illegal and unethical. The project owner and contributors are **NOT** responsible for misuse. See `SECURITY.md` for responsible disclosure instructions.

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
* Conservative by default: **OOB (out-of-band) checks are disabled unless explicitly enabled with `--enable-oob`**.

## Requirements

* Python 3.10+ recommended.

Create a `requirements.txt` file like:

```
requests>=2.28
beautifulsoup4>=4.12
charset-normalizer>=2.1
urllib3>=1.26
```

(Add other libraries your code actually imports.)

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

Run the tool:

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

Run with OOB checks explicitly enabled (default is safe/off):

```bash
python sql-injection-tool.py -u "http://example.com/search?q=test" -p q --enable-oob
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

## Recommended CLI options

* `-u, --url` : Target URL
* `-p, --param` : Parameter name to test
* `-X, --method` : HTTP method (GET or POST)
* `-d, --data` : POST data (when using POST)
* `--interactive` : Run menu-based interactive interface
* `--auto-run` : Execute all configured tests automatically on provided URL
* `--enable-oob` : Enable OOB/callback tests (disabled by default)
* `--output` : Output file (JSON)
* `--verbose` : Verbose logging

## Output format

Results are stored in JSON. Example:

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

## Security & Responsible Testing

* Only test systems you own or have written permission to test.
* Prefer isolated test environments (VMs, containers, intentionally vulnerable apps).
* Default is **safe mode**: no OOB callbacks unless explicitly enabled.
* Never store or publish sensitive data you discover; follow responsible disclosure.
* See `SECURITY.md` for how to report vulnerabilities responsibly.

## Contributing

Contributions are welcome:

1. Fork the repository.
2. Create a feature branch and write tests.
3. Run linting and tests locally.
4. Open a Pull Request.

Suggested additions:

* Add GitHub Actions workflow (`.github/workflows/ci.yml`) to run lint + tests.
* Use `ruff` or `flake8` and `pytest` in CI.

See `CONTRIBUTING.md` for details.

## License

This project is licensed under the **MIT License**. See `LICENSE` file.

## Changelog

* `v1.0.0` - Initial release: basic scanner, interactive mode, JSON output, README.

## FAQ

**Q: Does this tool exploit systems?**
A: It detects SQL injection indicators and produces evidence. Exploit-like behavior is not enabled by default; any deeper testing must only be used in controlled labs.

**Q: Can I test production sites?**
A: No — never test production or third-party sites without explicit permission.

## Contact

If you find a bug or a security issue:

* Open an [Issue](https://github.com/mino756/sql-injection-tool/issues)
* Or email: [your-email@example.com](otfmino@gmail.com) (replace with a real contact)

---

*Thank you for using this tool responsibly.*

