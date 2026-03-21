"""JavaScript/TypeScript 安全扫描器（基于正则模式）"""
import re
from pathlib import Path
from typing import List, Optional

from ..models import Vulnerability, Severity


class JSScanner:
    """JavaScript/TypeScript 安全扫描器"""

    # 危险函数
    DANGEROUS_FUNCTIONS = {
        'eval': ('Code Injection via eval()', Severity.CRITICAL, 'CWE-94'),
        'Function()': ('Code Injection via Function constructor', Severity.CRITICAL, 'CWE-94'),
        'setTimeout(str,': ('Indirect Code Injection via setTimeout', Severity.HIGH, 'CWE-94'),
        'setInterval(str,': ('Indirect Code Injection via setInterval', Severity.HIGH, 'CWE-94'),
        'document.write': ('XSS via document.write()', Severity.HIGH, 'CWE-79'),
        'innerHTML': ('XSS via innerHTML', Severity.HIGH, 'CWE-79'),
        'outerHTML': ('XSS via outerHTML', Severity.HIGH, 'CWE-79'),
        'jq.html(': ('XSS via jQuery .html()', Severity.HIGH, 'CWE-79'),
    }

    # XSS 相关模式
    XSS_PATTERNS = [
        (r'innerHTML\s*=\s*[^;]*\+', 'Potential XSS: innerHTML with concatenation'),
        (r'document\.write\s*\(', 'Potential XSS: document.write'),
        (r'\.html\s*\(\s*[^;]*\+', 'Potential XSS: jQuery .html with concatenation'),
        (r'regExp\s*\(\s*[^)]+\+', 'Potential XSS: RegExp with user input'),
        (r'eval\s*\(', 'Code Injection: eval()'),
    ]

    # SQL/NoSQL 注入
    INJECTION_PATTERNS = [
        (r'(?:query|find|insert|update|delete)\s*\(.*\+', 'NoSQL/Query Injection'),
        (r'\$\w+\s*:\s*[^,]*\+', 'MongoDB Injection Pattern'),
    ]

    # 硬编码密钥
    SECRET_PATTERNS = [
        (r'password\s*[=:]\s*["\'][^"\']{3,}["\']', 'Hardcoded Password', Severity.CRITICAL),
        (r'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', 'Hardcoded API Key', Severity.CRITICAL),
        (r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Secret', Severity.CRITICAL),
        (r'bearer\s+[A-Za-z0-9_\-\.]+', 'Hardcoded Bearer Token', Severity.CRITICAL),
        (r'aws_access_key', 'Hardcoded AWS Key', Severity.CRITICAL),
        (r'ghp_[A-Za-z0-9]{36}', 'Hardcoded GitHub Token', Severity.CRITICAL),
        (r'sk-[A-Za-z0-9]{48}', 'Hardcoded OpenAI Key', Severity.CRITICAL),
    ]

    # CSRF
    CSRF_PATTERNS = [
        (r'request\s*\(.*without.*csrf', 'Missing CSRF Protection'),
        (r'csrf.*disabled', 'CSRF Protection Disabled'),
    ]

    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """扫描 JS/TS 文件"""
        if not self._is_js_file(file_path):
            return []

        try:
            source = file_path.read_text(encoding='utf-8')
        except Exception:
            return []

        return self.scan_source(source, str(file_path))

    def scan_source(self, source: str, file_path: str = "") -> List[Vulnerability]:
        """扫描源代码"""
        vulns = []

        # 检测危险函数
        for func, (desc, severity, cwe) in self.DANGEROUS_FUNCTIONS.items():
            if func in source:
                lines = source.split('\n')
                for i, line in enumerate(lines, 1):
                    if func in line:
                        vulns.append(Vulnerability(
                            id=f"VULN-{len(vulns)+1:04d}",
                            title=func + ' Usage',
                            description=desc,
                            severity=severity,
                            file=file_path,
                            line=i,
                            code_snippet=line.strip(),
                            cwe=cwe,
                            ai_confidence=0.9,
                        ))

        # XSS 检测
        for pattern, desc in self.XSS_PATTERNS:
            for match in re.finditer(pattern, source, re.MULTILINE):
                line_no = source[:match.start()].count('\n') + 1
                line_content = source.split('\n')[line_no - 1].strip()
                vulns.append(Vulnerability(
                    id=f"VULN-{len(vulns)+1:04d}",
                    title="XSS Vulnerability",
                    description=desc,
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_no,
                    code_snippet=line_content,
                    cwe="CWE-79",
                    owasp="A03:2021",
                    ai_confidence=0.88,
                ))

        # 密钥检测
        for pattern, desc, severity in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_no = source[:match.start()].count('\n') + 1
                line_content = source.split('\n')[line_no - 1].strip()
                vulns.append(Vulnerability(
                    id=f"VULN-{len(vulns)+1:04d}",
                    title="Hardcoded Secret",
                    description=desc,
                    severity=severity,
                    file=file_path,
                    line=line_no,
                    code_snippet=line_content,
                    cwe="CWE-798",
                    ai_confidence=0.98,
                ))

        return vulns

    def _is_js_file(self, path: Path) -> bool:
        return path.suffix in {'.js', '.jsx', '.ts', '.tsx', '.vue'}
