import requests
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import hashlib

class APISecurityScanner:
    def __init__(self):
        self.vulnerabilities = []

    def check_sql_injection(self, url, params):
        payloads = ["' OR '1'='1", "1' OR '1'='1' --", "admin'--"]
        for key in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[key] = payload
                try:
                    response = requests.get(url, params=test_params, timeout=3)
                    if any(err in response.text.lower() for err in ['sql', 'mysql', 'syntax error']):
                        return {"vulnerable": True, "type": "SQL Injection", "param": key}
                except:
                    pass
        return {"vulnerable": False}

    def check_xss(self, url, params):
        xss_payload = "<script>alert('XSS')</script>"
        for key in params:
            test_params = params.copy()
            test_params[key] = xss_payload
            try:
                response = requests.get(url, params=test_params, timeout=3)
                if xss_payload in response.text:
                    return {"vulnerable": True, "type": "XSS", "param": key}
            except:
                pass
        return {"vulnerable": False}

    def check_headers(self, url):
        missing_headers = []
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        try:
            response = requests.get(url, timeout=3)
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            return {"missing_headers": missing_headers, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}

    def check_sensitive_info(self, url):
        sensitive_patterns = {
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)',
            'password': r'password["\']?\s*[:=]\s*["\']?([^\s"\']+)',
            'token': r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_.-]+)'
        }
        findings = []
        try:
            response = requests.get(url, timeout=3)
            for key, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    findings.append({"type": key, "count": len(matches)})
        except:
            pass
        return findings

    def scan(self, url, params=None):
        if params is None:
            params = {}

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "scan_id": hashlib.md5(f"{url}{datetime.now()}".encode()).hexdigest()[:8],
            "vulnerabilities": []
        }

        # Tests en parallèle
        with ThreadPoolExecutor(max_workers=4) as executor:
            sql_future = executor.submit(self.check_sql_injection, url, params)
            xss_future = executor.submit(self.check_xss, url, params)
            headers_future = executor.submit(self.check_headers, url)
            sensitive_future = executor.submit(self.check_sensitive_info, url)

            sql_result = sql_future.result()
            xss_result = xss_future.result()
            headers_result = headers_future.result()
            sensitive_result = sensitive_future.result()

        # Compilation des résultats
        if sql_result.get("vulnerable"):
            results["vulnerabilities"].append(sql_result)
        if xss_result.get("vulnerable"):
            results["vulnerabilities"].append(xss_result)
        if headers_result.get("missing_headers"):
            results["vulnerabilities"].append({
                "type": "Missing Security Headers",
                "headers": headers_result["missing_headers"]
            })
        if sensitive_result:
            results["vulnerabilities"].append({
                "type": "Sensitive Information Exposure",
                "findings": sensitive_result
            })

        results["severity"] = self._calculate_severity(results["vulnerabilities"])
        return results

    def _calculate_severity(self, vulns):
        if not vulns:
            return "LOW"
        high_risk = any(v.get("type") in ["SQL Injection", "XSS"] for v in vulns)
        return "HIGH" if high_risk else "MEDIUM"
