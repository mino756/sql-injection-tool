# sql-injection-tool v2.0.1
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

## 🛠️ Installation
```bash
git clone https://github.com/yourusername/sqli-scanner.git
cd sqli-scanner
pip install -r requirements.txt
```
## Prerequisites
Python 3.7 or higher
pip package manage

## ✨ Features
🔍 Detection Methods
- Error-based SQL Injection - Classic error message detection

- Union-based SQL Injection - UNION query exploitation

- Boolean-based Blind SQLi - True/false condition testing

- Time-based Blind SQLi - Response timing analysis

- Stacked Queries - Multiple query execution

- Out-of-Band (OOB) - External network call testing

- Content-based Analysis - Response comparison techniques

.. 🛠️ Advanced Capabilities

- Automatic Parameter Discovery - From URLs, forms, and JavaScript

- DBMS Fingerprinting - MySQL, MSSQL, Oracle, PostgreSQL detection

- WAF Bypass Techniques - Payload obfuscation and encoding

- Multi-threaded Scanning - Concurrent request processing

- Batch Processing - Scan multiple targets from file

- Interactive Mode - User-friendly guided scanning

- Comprehensive Reporting - JSON, CSV, and HTML outputs

.. 📊 Output & Reporting
JSON Reports - Structured data for automation

CSV Export - Spreadsheet-friendly format

HTML Reports - Visual, human-readable format

Scan Summary - Executive overview with statistics

Detailed Findings - Individual test results with confidence levels

## 📖 Usage Examples
Basic Scanning
```bash
python sqli_scanner.py -u "http://example.com/search?q=test" -p q
```
# Auto-discover parameters
```bash
python sqli_scanner.py -u "http://example.com/login" --discover-params
```
# POST request testing
```bash
python sqli_scanner.py -u "http://example.com/login" -X POST -p username
```

# High-intensity scan with custom headers
```bash
python sqli_scanner.py -u "http://api.example.com/data" \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  --level 3 \
  --threads 15
```
# Specific DBMS targeting
```bash
python sqli_scanner.py -u "http://example.com" --dbms mysql --tests union,boolean
```
# With proxy support for debugging
```bash
python sqli_scanner.py -u "http://example.com" --proxy "http://127.0.0.1:8080"
```
# WAF bypass mode
```bash
python sqli_scanner.py -u "http://example.com" --waf-bypass --encoding double-url
Batch Processing
```
```bash
# Scan multiple URLs from file
python sqli_scanner.py -i targets.txt -b -o batch_results
```
# Resume interrupted scan
```bash
python sqli_scanner.py --resume previous_scan.json
```
# Batch scan with delay between requests
```bash
python sqli_scanner.py -i targets.txt --delay 2 --threads 3
```
## Interactive Mode
```bash
python sqli_scanner.py
```
Interactive mode provides a guided experience with:

URL input validation

Parameter discovery and selection

Real-time progress updates

Immediate result display

## ⚙️ Command Line Reference
- Target Options
- Option	Description
-u, --url URL	Target URL (required for batch mode)

-p, --param PARAM	Specific parameter to test

-X, --method {GET,POST}	HTTP method (default: GET)

--discover-params	Auto-discover parameters from forms/JS

- Request Options

- Option	Description

-H, --header HEADER	Custom HTTP header (key=value)

-P, --params PARAMS	Static parameters (key=value)

`-A, --user-agent AGENT	

