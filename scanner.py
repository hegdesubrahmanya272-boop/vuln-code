import requests
import socket
import re
from owasp_checks import audit_owasp_risks
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0

def analyze_link_vulnerabilities(url, session):
    issues = []
    try:
        response = session.get(url, timeout=3)
        headers = response.headers
        if not url.startswith("https"):
            issues.append("Missing HTTPS Encryption")
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options (Clickjacking)")
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy (XSS Risk)")
    except Exception:
        pass
    return issues

def scan_website_stream(url, username=None, password=None):
    """Universal scanner that dynamically discovers login forms and authenticates against any URL."""
    try:
        yield f"INFO: Initializing dynamic session configuration against: {url}\n"
        session = requests.Session()
        
        if username and password:
            yield "INFO: Searching target for authentication access points...\n"
            try:
                init_res = session.get(url, timeout=5)
                soup = BeautifulSoup(init_res.text, "html.parser")
                
                form = None
                for f in soup.find_all("form"):
                    form_text = str(f).lower()
                    if "pass" in form_text or "log" in form_text or "user" in form_text:
                        form = f
                        break
                
                if not form:
                    login_check_url = url.rstrip("/") + "/login"
                    init_res = session.get(login_check_url, timeout=5)
                    soup = BeautifulSoup(init_res.text, "html.parser")
                    form = soup.find("form")
                
                if form:
                    action = form.get("action", "")
                    target_login_url = urljoin(url, action)
                    
                    payload = {}
                    inputs = form.find_all("input")
                    
                    for inp in inputs:
                        input_type = inp.get("type", "").lower()
                        input_name = inp.get("name")
                        
                        if not input_name:
                            continue
                            
                        if input_type in ["text", "email"] or "user" in input_name.lower() or "uid" in input_name.lower():
                            payload[input_name] = username
                        elif input_type == "password" or "pass" in input_name.lower():
                            payload[input_name] = password
                        elif input_type in ["hidden", "submit"]:
                            payload[input_name] = inp.get("value", "")

                    yield f"INFO: Dynamic form signature mapped. Processing authentication request...\n"
                    
                    login_res = session.post(target_login_url, data=payload, timeout=5, allow_redirects=True)
                    res_text = login_res.text.lower()
                    
                    failure_keywords = ["invalid", "failed", "incorrect", "wrong password", "unauthorized"]
                    has_failure_text = any(kw in res_text for kw in failure_keywords)
                    
                    if login_res.status_code == 200 and not has_failure_text:
                        yield "INFO: Login successfully! Session tokens established.\n"
                    else:
                        yield "INFO: Unsuccessful login! Server rejected credentials based on page fingerprint.\n"
                else:
                    yield "INFO: No clear login forms detected on target entrypoints. Scanning publicly...\n"
                    
            except Exception as login_err:
                yield f"INFO: Unsuccessful login! Target architecture mapping failed: {str(login_err)}\n"
        else:
            yield "INFO: No credentials provided. Proceeding with anonymous public scan...\n"

        response = session.get(url, timeout=5)
        yield f"INFO: Base target responded with status code {response.status_code}\n"
        
        yield "INFO: Running technology detection layers...\n"
        server = response.headers.get("Server")
        if server: yield f"INFO: Server Header detected -> {server}\n"

        html = response.text
        jquery = re.search(r'jquery[-.]?(\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if jquery: yield f"INFO: jQuery Version found -> {jquery.group(1)}\n"

        for cookie in response.cookies:
            secure_status = "Secure" if cookie.secure else "Insecure"
            yield f"INFO: Cookie Found -> {cookie.name} [{secure_status}]\n"

        yield "INFO: Initializing Hidden Directory Buster framework...\n"
        endpoints = {
            "/robots.txt": "Information Leakage",
            "/sitemap.xml": "Information Leakage",
            "/.env": "CRITICAL: Exposed Environment Configuration File",
            "/.git/HEAD": "HIGH: Exposed Git Repository Directory"
        }

        for endpoint, vulnerability in endpoints.items():
            try:
                test_url = url.rstrip("/") + "/" + endpoint.lstrip("/")
                r = session.get(test_url, timeout=2, allow_redirects=False)
                if r.status_code == 200:
                    yield f"VULN: 🚨 [ENDPOINT EXPOSED] -> {test_url} ({vulnerability})\n"
            except Exception:
                pass

        yield "INFO: Beginning deep recursive link analysis queue...\n"
        soup = BeautifulSoup(response.text, "html.parser")
        visited = set()
        queue = [urljoin(url, link.get("href")) for link in soup.find_all("a") if link.get("href")]

        count = 0
        while queue and count < 1000:
            current_link = queue.pop(0)
            if current_link in visited or urlparse(current_link).netloc != urlparse(url).netloc:
                continue
                
            visited.add(current_link)
            count += 1
            yield f"CRAWL: New link analyzed -> {current_link}\n"
            
            loopholes = analyze_link_vulnerabilities(current_link, session)
            if loopholes:
                for issue in loopholes:
                    yield f"VULN: ⚠️ Loophole found -> {issue} on {current_link}\n"

    except Exception as e:
        yield f"VULN: Execution error encountered: {str(e)}\n"
        
    yield "INFO: Security operation completely finished.\n"