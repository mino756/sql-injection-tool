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
