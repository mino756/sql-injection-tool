# sql-injection-tool
Advanced SQL Injection tool - Enterprise-grade security assessment tool for comprehensive SQL injection detection. Supports multiple DBMS, automated parameter discovery, concurrent scanning, and detailed vulnerability reporting for penetration testers and security researchers.

## Features

- **Multiple Detection Methods**: Error-based, Union-based, Boolean-based, Time-based, Blind, Stacked Queries
- **DBMS Fingerprinting**: Automatic database management system detection
- **Parameter Discovery**: Automatic discovery of parameters from URLs, forms, and JavaScript
- **WAF Bypass**: Built-in payload obfuscation techniques
- **Multi-threaded**: Concurrent scanning for improved performance
- **Comprehensive Reporting**: JSON, CSV, and HTML report generation
- **Batch Processing**: Scan multiple URLs from a file
- **Interactive Mode**: User-friendly interactive scanning

## Installation

```bash
git clone https://github.com/yourusername/sqli-scanner.git
cd sqli-scanner
pip install -r requirements.txt

## Requirements
Python 3.7+

requests

urllib3

Usage
Basic Scan
bash
python sqli_scanner.py -u "http://example.com/page?id=1" -p id
Interactive Mode
bash
python sqli_scanner.py
Advanced Scan
bash
python sqli_scanner.py -u "http://example.com/login" -X POST -p username \
  -H "Content-Type=application/json" --threads 10 -o scan_results --level 3
Batch Scan
bash
python sqli_scanner.py -i urls.txt -b -o batch_scan
Command Line Options
Target Options
-u, --url: Target URL

-p, --param: Specific parameter to test

-X, --method: HTTP method (GET/POST)

--discover-params: Automatically discover parameters

Request Options
-H, --header: Custom HTTP headers

-A, --user-agent: Custom User-Agent

--proxy: HTTP proxy

--timeout: Request timeout

-k, --insecure: Skip SSL verification

Scan Options
--dbms: Target DBMS (auto/mysql/mssql/oracle/postgres)

--level: Scan intensity (1-3)

--tests: Specific tests to run

--threads: Number of concurrent threads

Output Options
-o, --output: Output file

--format: Output format (json/csv/html/all)

-v, --verbose: Verbose output

--debug: Debug mode

Output Formats
The scanner generates three report formats:

JSON: Structured data for programmatic processing

CSV: Spreadsheet-friendly format

HTML: Human-readable web report

Examples
Test Specific Parameter
bash
python sqli_scanner.py -u "http://test.com/search?q=test" -p q
Full Scan with Custom Headers
bash
python sqli_scanner.py -u "http://test.com/api" -X POST \
  -H "Authorization: Bearer token" -H "Content-Type: application/json" \
  --discover-params --level 3
Batch Processing
bash
python sqli_scanner.py -i targets.txt -b --threads 5 -o results
Legal Disclaimer
This tool is intended for security testing and educational purposes only. Only use on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this tool.

License
MIT License - see LICENSE file for details.
