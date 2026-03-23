"""AST-based vulnerability scanner"""
import ast
import re
import logging
from pathlib import Path
from typing import List, Dict

from .models import Vulnerability, Severity


logger = logging.getLogger(__name__)


# Security patterns for Python
PYTHON_PATTERNS = {
    "sql_injection": {
        "pattern": r"execute\s*\(\s*['\"].*\+|f['\"].*\{.*\}.*execute",
        "severity": Severity.CRITICAL,
        "title": "SQL Injection Risk",
        "description": "Possible SQL injection vulnerability detected"
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": Severity.HIGH,
        "title": "Use of eval()",
        "description": "eval() is dangerous and can execute arbitrary code"
    },
    "exec_usage": {
        "pattern": r"\bexec\s*\(",
        "severity": Severity.HIGH,
        "title": "Use of exec()",
        "description": "exec() is dangerous and can execute arbitrary code"
    },
    "hardcoded_password": {
        "pattern": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "severity": Severity.HIGH,
        "title": "Hardcoded Password",
        "description": "Hardcoded password detected in source code"
    },
    "hardcoded_secret": {
        "pattern": r"(api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
        "severity": Severity.HIGH,
        "title": "Hardcoded Secret",
        "description": "Hardcoded API key, secret, or token detected"
    },
    "pickle_usage": {
        "pattern": r"pickle\.loads?\s*\(",
        "severity": Severity.HIGH,
        "title": "Use of pickle",
        "description": "pickle can execute arbitrary code during deserialization"
    },
    "subprocess_shell": {
        "pattern": r"subprocess\..*shell\s*=\s*True",
        "severity": Severity.MEDIUM,
        "title": "Subprocess with shell=True",
        "description": "shell=True can lead to shell injection vulnerabilities"
    },
    "insecure_hash": {
        "pattern": r"hashlib\.(md5|sha1)\s*\(",
        "severity": Severity.LOW,
        "title": "Insecure Hash Function",
        "description": "MD5/SHA1 are considered insecure for cryptographic purposes"
    },
}

# Security patterns for JavaScript
JS_PATTERNS = {
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": Severity.HIGH,
        "title": "Use of eval()",
        "description": "eval() is dangerous and can execute arbitrary code"
    },
    "innerHTML": {
        "pattern": r"\.innerHTML\s*=",
        "severity": Severity.MEDIUM,
        "title": "Use of innerHTML",
        "description": "innerHTML can lead to XSS vulnerabilities"
    },
    "document_write": {
        "pattern": r"document\.write\s*\(",
        "severity": Severity.MEDIUM,
        "title": "Use of document.write()",
        "description": "document.write can lead to XSS vulnerabilities"
    },
    "hardcoded_secret": {
        "pattern": r"(apiKey|api_key|secret|token|password)\s*[=:]\s*['\"][^'\"]+['\"]",
        "severity": Severity.HIGH,
        "title": "Hardcoded Secret",
        "description": "Hardcoded API key, secret, or token detected"
    },
}


class BaseScanner:
    """Base scanner class"""
    
    def __init__(self):
        self.logger = logger
    
    def _get_line_content(self, file_path: Path, line_number: int, context: int = 2) -> str:
        """Get line content with context"""
        try:
            lines = open(file_path, encoding='utf-8', errors='ignore').readlines()
            start = max(0, line_number - context - 1)
            end = min(len(lines), line_number + context)
            return ''.join(lines[start:end])
        except Exception:
            return ""


class PythonScanner(BaseScanner):
    """Python AST and regex scanner"""
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan Python file
        
        Args:
            file_path: Path to Python file
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            content = open(file_path, encoding='utf-8', errors='ignore').read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                for rule_id, pattern_config in PYTHON_PATTERNS.items():
                    if re.search(pattern_config["pattern"], line):
                        vuln = Vulnerability(
                            file=str(file_path),
                            line=i,
                            title=pattern_config["title"],
                            description=pattern_config["description"],
                            severity=pattern_config["severity"],
                            code_snippet=line.strip(),
                            rule_id=rule_id,
                        )
                        vulnerabilities.append(vuln)
            
            # AST-based checks
            vulnerabilities.extend(self._ast_scan(file_path, content))
            
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    def _ast_scan(self, file_path: Path, content: str) -> List[Vulnerability]:
        """AST-based security scan"""
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Check for assert statements (can be disabled with -O)
                if isinstance(node, ast.Assert):
                    vulnerabilities.append(Vulnerability(
                        file=str(file_path),
                        line=node.lineno,
                        title="Use of assert",
                        description="assert statements can be disabled with -O flag",
                        severity=Severity.LOW,
                        code_snippet="assert ...",
                        rule_id="assert_usage",
                    ))
                
                # Check for bare except
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    vulnerabilities.append(Vulnerability(
                        file=str(file_path),
                        line=node.lineno,
                        title="Bare except clause",
                        description="Bare except catches all exceptions including KeyboardInterrupt",
                        severity=Severity.LOW,
                        code_snippet="except:",
                        rule_id="bare_except",
                    ))
                
                # Check for potential command injection in subprocess
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'call' or node.func.attr == 'run':
                            for kw in node.keywords:
                                if kw.arg == 'shell':
                                    if isinstance(kw.value, ast.Constant) and kw.value.value:
                                        vulnerabilities.append(Vulnerability(
                                            file=str(file_path),
                                            line=node.lineno,
                                            title="Subprocess with shell=True",
                                            description="shell=True can lead to shell injection",
                                            severity=Severity.MEDIUM,
                                            code_snippet="subprocess with shell=True",
                                            rule_id="subprocess_shell",
                                        ))
        except SyntaxError:
            pass
        
        return vulnerabilities


class JSScanner(BaseScanner):
    """JavaScript/TypeScript regex scanner"""
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan JavaScript/TypeScript file
        
        Args:
            file_path: Path to JS/TS file
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            content = open(file_path, encoding='utf-8', errors='ignore').read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                for rule_id, pattern_config in JS_PATTERNS.items():
                    if re.search(pattern_config["pattern"], line):
                        vuln = Vulnerability(
                            file=str(file_path),
                            line=i,
                            title=pattern_config["title"],
                            description=pattern_config["description"],
                            severity=pattern_config["severity"],
                            code_snippet=line.strip(),
                            rule_id=rule_id,
                        )
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
