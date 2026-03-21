"""测试"""
import pytest
from src.ai_security_scanner import SecurityScanner
from src.models import Severity


class TestSecurityScanner:
    def test_scan_python_sql_injection(self):
        code = '''
def login(username, password):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
'''
        scanner = SecurityScanner()
        vulns = scanner.py_scanner.scan_source(code)
        assert any(v.title == "SQL Injection" for v in vulns)

    def test_scan_python_eval(self):
        code = 'result = eval(user_input)'
        scanner = SecurityScanner()
        vulns = scanner.py_scanner.scan_source(code)
        assert any("eval" in v.title for v in vulns)

    def test_scan_js_xss(self):
        code = 'element.innerHTML = userInput + "<script>"'
        scanner = SecurityScanner()
        vulns = scanner.js_scanner.scan_source(code)
        assert any(v.title == "XSS Vulnerability" for v in vulns)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
