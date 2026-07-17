import re

def audit_owasp_risks(url, response):
    """
    Analyzes target HTTP data streams against compliance criteria.
    Outputs validation stream signals to stderr/stdout.
    """
    findings = []
    headers = response.headers
    content = response.text

    # 1. Cryptographic Auditor (A04:2021)
    if url.startswith("http://"):
        findings.append("VULN: [CRYPTO FAILURE] -> Target site utilizing unencrypted protocol stream context.")
    elif "Strict-Transport-Security" not in headers:
        findings.append("VULN: [CRYPTO FAILURE] -> Missing Strict-Transport-Security (HSTS) validation header.")

    # 2. Exception Tracker (A10:2021)
    error_signatures = [
        r"Fatal error:", r"Traceback \(most recent call last\)", 
        r"SQL syntax", r"Exception occurred:"
    ]
    for pattern in error_signatures:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(f"VULN: [VERBOSE ERROR LEAK] -> System exception context exposure detected.")
            break

    # 3. Rate Limit Evaluator (A09:2021)
    # Check if target explicitly warns about lack of protective rate mitigation headers
    if "X-RateLimit-Limit" not in headers and "Retry-After" not in headers:
        findings.append("INFO: [LOGGING/RATE LIMIT FAILURE] -> Endpoint metrics lack visible rate-limiting thresholds.")

    return findings