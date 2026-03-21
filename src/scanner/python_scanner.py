"""Python AST 静态扫描器"""
import ast
import re
from pathlib import Path
from typing import List, Optional, Set, Union
from dataclasses import dataclass, field

from ..models import Vulnerability, Severity


@dataclass
class ScanContext:
    """扫描上下文"""
    file_path: str = ""
    source_code: str = ""
    tree: Optional[ast.AST] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    current_function: Optional[str] = None
    current_class: Optional[str] = None


class PythonScanner:
    """Python AST 安全扫描器"""

    # 危险函数/模式
    DANGEROUS_BUILTINS = {
        'eval', 'exec', 'compile', 'open', 'input',
        '__import__', 'getattr', 'setattr', 'delattr',
    }

    # SQL 注入关键词
    SQL_PATTERNS = [
        r'execute\s*\(',
        r'executemany\s*\(',
        r'cursor\.',
        r'sql\s*=',
        r'query\s*=',
        r'\"SELECT',
        r'\"INSERT',
        r'\"UPDATE',
        r'\"DELETE',
        r'\"DROP',
        r'\"CREATE',
    ]

    # 硬编码密钥正则
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\'](?!{{|{{)[^"\']{3,}["\']', 'Hardcoded Password'),
        (r'api_key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API Key'),
        (r'secret\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded Secret'),
        (r'token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'Hardcoded Token'),
        (r'aws_access_key', 'Hardcoded AWS Key'),
        (r'aws_secret_key', 'Hardcoded AWS Secret'),
        (r'BEGIN\s+(RSA\s+)?PRIVATE\s+KEY', 'Hardcoded Private Key'),
        (r'ghp_[A-Za-z0-9]{36}', 'Hardcoded GitHub Token'),
        (r'sk-[A-Za-z0-9]{48}', 'Hardcoded OpenAI Key'),
    ]

    # 弱加密算法
    WEAK_CRYPTO = {
        'md5': 'MD5 (易受碰撞攻击)',
        'sha1': 'SHA1 (易受碰撞攻击)',
        'des': 'DES (56位密钥，易被破解)',
        'rc4': 'RC4 (存在偏差攻击)',
        'blowfish': 'Blowfish (可接受，建议用AES)',
    }

    def __init__(self):
        self.context: Optional[ScanContext] = None

    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """扫描单个 Python 文件"""
        if not self._is_python_file(file_path):
            return []

        try:
            source = file_path.read_text(encoding='utf-8')
        except Exception:
            return []

        return self.scan_source(source, str(file_path))

    def scan_source(self, source: str, file_path: str = "") -> List[Vulnerability]:
        """扫描源代码"""
        self.context = ScanContext(
            file_path=file_path,
            source_code=source,
        )

        try:
            self.context.tree = ast.parse(source)
        except SyntaxError:
            return []

        # 遍历 AST 节点
        for node in ast.walk(self.context.tree):
            self._visit_node(node)

        return self.context.vulnerabilities

    def _visit_node(self, node: ast.AST):
        """访问 AST 节点"""
        methods = {
            ast.FunctionDef: self._visit_function,
            ast.AsyncFunctionDef: self._visit_function,
            ast.Call: self._visit_call,
            ast.Assign: self._visit_assign,
            ast.Attribute: self._visit_attribute,
        }

        visitor = methods.get(type(node))
        if visitor:
            visitor(node)

    def _visit_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]):
        """访问函数定义"""
        self.context.current_function = node.name

        # 检查危险函数名
        if node.name in ['eval', 'exec', 'compile']:
            self._add_vuln(
                title="Dangerous Function Usage",
                description=f"使用危险函数 {node.name}，可能导致代码注入",
                severity=Severity.CRITICAL,
                node=node,
            )

    def _visit_call(self, node: ast.Call):
        """访问函数调用"""
        # 检查危险函数
        func_name = self._get_func_name(node.func)

        if func_name == 'eval':
            self._add_vuln(
                title="Code Injection via eval()",
                description="eval() 执行任意代码，存在严重安全风险",
                severity=Severity.CRITICAL,
                node=node,
                cwe="CWE-94",
                owasp="A03:2021",
            )

        elif func_name == 'exec':
            self._add_vuln(
                title="Code Injection via exec()",
                description="exec() 执行任意代码，存在严重安全风险",
                severity=Severity.CRITICAL,
                node=node,
                cwe="CWE-94",
            )

        elif func_name == 'pickle.loads' or func_name == 'pickle.load':
            self._add_vuln(
                title="Insecure Deserialization",
                description="pickle 反序列化可能执行恶意代码",
                severity=Severity.CRITICAL,
                node=node,
                cwe="CWE-502",
                owasp="A08:2021",
            )

        elif func_name == 'yaml.load':
            self._add_vuln(
                title="YAML Deserialization Vulnerability",
                description="yaml.load() 默认不安全，请使用 yaml.safe_load()",
                severity=Severity.HIGH,
                node=node,
                cwe="CWE-502",
            )

        elif func_name == 'subprocess.Popen' or func_name == 'os.system':
            # 检查是否有用户输入拼接到命令
            if self._has_user_input(node):
                self._add_vuln(
                    title="Command Injection",
                    description="用户输入可能拼接到系统命令，存在命令注入风险",
                    severity=Severity.CRITICAL,
                    node=node,
                    cwe="CWE-78",
                    owasp="A03:2021",
                )

        elif func_name == 'execute' or func_name == 'executemany':
            # 检查 SQL 拼接
            if self._has_sql_concatenation(node):
                self._add_vuln(
                    title="SQL Injection",
                    description="SQL 语句拼接了用户输入，存在注入风险",
                    severity=Severity.CRITICAL,
                    node=node,
                    cwe="CWE-89",
                    owasp="A03:2021",
                )

    def _visit_assign(self, node: ast.Assign):
        """访问赋值语句"""
        # 检查硬编码密钥
        for pattern, title in self.SECRET_PATTERNS:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if var_name in pattern.lower() or re.search(pattern, self.context.source_code):
                        pass  # 进一步检查

        # 检查弱加密
        code = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        for weak_algo, desc in self.WEAK_CRYPTO.items():
            if weak_algo in code:
                self._add_vuln(
                    title=f"Weak Cryptography: {weak_algo.upper()}",
                    description=desc,
                    severity=Severity.MEDIUM,
                    node=node,
                    cwe="CWE-327",
                )

    def _visit_attribute(self, node: ast.Attribute):
        """访问属性访问"""
        # 检查 .format() 和 f-string 混用
        if hasattr(node.value, 's') and '%' in str(getattr(node.value, 's', '')):
            pass

    def _has_user_input(self, node: ast.Call) -> bool:
        """检查调用是否包含用户输入"""
        UNSAFE_SOURCES = {'request.args', 'request.form', 'request.json',
                          'request.data', 'input', 'sys.argv', 'os.environ'}

        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attr_name = ast.unparse(child) if hasattr(ast, 'unparse') else ''
                if any(unsafe in attr_name for unsafe in UNSAFE_SOURCES):
                    return True
        return False

    def _has_sql_concatenation(self, node: ast.Call) -> bool:
        """检查 SQL 语句是否拼接"""
        for child in ast.walk(node):
            if isinstance(child, ast.BinOp):
                return True
        return False

    def _get_func_name(self, func) -> str:
        """获取函数名"""
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            return func.attr
        elif isinstance(func, ast.Call):
            return self._get_func_name(func.func)
        return ''

    def _add_vuln(
        self,
        title: str,
        description: str,
        severity: Severity,
        node: ast.AST,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
    ):
        """添加漏洞"""
        vuln = Vulnerability(
            id=self._gen_id(),
            title=title,
            description=description,
            severity=severity,
            file=self.context.file_path,
            line=node.lineno if hasattr(node, 'lineno') else 0,
            column=node.col_offset if hasattr(node, 'col_offset') else None,
            function=self.context.current_function,
            code_snippet=self._get_code_snippet(node),
            cwe=cwe,
            owasp=owasp,
            ai_confidence=0.95,
        )
        self.context.vulnerabilities.append(vuln)

    def _gen_id(self) -> str:
        """生成漏洞 ID"""
        return f"VULN-{len(self.context.vulnerabilities) + 1:04d}"

    def _get_code_snippet(self, node: ast.AST) -> str:
        """获取代码片段"""
        if not hasattr(node, 'lineno'):
            return ""

        lines = self.context.source_code.split('\n')
        line_no = node.lineno - 1

        if 0 <= line_no < len(lines):
            return lines[line_no].strip()

        return ""

    def _is_python_file(self, path: Path) -> bool:
        return path.suffix == '.py' and not path.name.startswith('test_')
