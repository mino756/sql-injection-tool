## 🔒 Security Policy

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Active support |
| 1.0.x   | ❌ End of life    |

### Reporting a Vulnerability

We take the security of our SQL injection tool seriously. If you believe you've found a security vulnerability, please follow these steps:

#### 🚨 Private Disclosure Process
1. **DO NOT** disclose the vulnerability publicly until it has been addressed
2. Send an email to `otfmino}gmail.com` with:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any proof-of-concept code (if available)
3. You should receive a response within **48 hours**
4. We will work with you to understand and validate the issue

#### 📋 What to Include in Your Report
- **Vulnerability Type**: (e.g., RCE, information disclosure, etc.)
- **Affected Component**: Specific module or function
- **Reproduction Steps**: Clear, step-by-step instructions
- **Impact**: Potential security implications
- **Environment**: OS, Python version, dependencies

### Security Best Practices for Users

#### ⚠️ Legal Usage
- Only use on systems you own or have explicit permission to test
- Obtain proper authorization before scanning
- Compliance with local laws and regulations is mandatory
- Educational and authorized penetration testing only

#### 🔐 Safe Deployment
```bash
# Run in isolated environment
python -m venv sqli-scanner-env
source sqli-scanner-env/bin/activate
pip install -r requirements.txt
```
# Use with caution in production-like environments
```bash
python sqli_scanner.py --timeout 5 --threads 3
```
