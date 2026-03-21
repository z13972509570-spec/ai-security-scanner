"""主扫描器 — 协调 AST 扫描和 AI 修复生成"""
import time
import os
from pathlib import Path
from typing import List, Optional, Literal
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .scanner import PythonScanner, JSScanner
from .models import Vulnerability, ScanResult, Severity


@dataclass
class ScanConfig:
    """扫描配置"""
    extensions: List[str] = None
    exclude_dirs: List[str] = None
    max_file_size_kb: int = 1024
    n_workers: int = 4
    use_ai_fix: bool = True
    ai_provider: Literal["openai", "anthropic", "ollama"] = "openai"
    ai_model: str = "gpt-4o-mini"

    def __post_init__(self):
        self.extensions = self.extensions or ['.py', '.js', '.jsx', '.ts', '.tsx']
        self.exclude_dirs = self.exclude_dirs or [
            'node_modules', '__pycache__', '.git', 'venv', 'env',
            '.venv', 'build', 'dist', '.eggs', '*.egg-info'
        ]


class SecurityScanner:
    """AI 安全扫描器主类"""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.py_scanner = PythonScanner()
        self.js_scanner = JSScanner()

    def scan(self, path: str) -> ScanResult:
        """
        扫描文件或目录

        Args:
            path: 文件或目录路径

        Returns:
            ScanResult: 扫描结果
        """
        start_time = time.time()
        p = Path(path)

        result = ScanResult()

        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = self._collect_files(p)
        else:
            result.errors.append(f"路径不存在: {path}")
            return result

        result.scanned_files = len(files)

        # 并发扫描
        with ThreadPoolExecutor(max_workers=self.config.n_workers) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in files}
            for future in as_completed(futures):
                vulns = future.result()
                result.vulnerabilities.extend(vulns)

        result.scanned_lines = sum(
            len(open(f, encoding='utf-8', errors='ignore').readlines())
            for f in files if f.exists()
        )
        result.scan_time_seconds = time.time() - start_time

        return result

    def _collect_files(self, directory: Path) -> List[Path]:
        """收集扫描文件"""
        files = []
        for ext in self.config.extensions:
            for f in directory.rglob(f'*{ext}'):
                # 排除目录
                if any(ex in f.parts for ex in self.config.exclude_dirs):
                    continue
                # 排除大文件
                if f.stat().st_size > self.config.max_file_size_kb * 1024:
                    continue
                files.append(f)
        return files

    def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """扫描单个文件"""
        if file_path.suffix == '.py':
            return self.py_scanner.scan_file(file_path)
        elif file_path.suffix in {'.js', '.jsx', '.ts', '.tsx'}:
            return self.js_scanner.scan_file(file_path)
        return []

    def generate_fixes(self, vulns: List[Vulnerability]) -> List[str]:
        """使用 AI 生成修复代码"""
        fixes = []
        for vuln in vulns:
            fix = self._ai_fix(vuln)
            fixes.append(fix)
        return fixes

    def _ai_fix(self, vuln: Vulnerability) -> str:
        """调用 AI 生成单个漏洞的修复代码"""
        from openai import OpenAI

        prompt = f"""你是安全工程师。以下代码存在漏洞:

文件: {vuln.file}:{vuln.line}
漏洞: {vuln.title}
描述: {vuln.description}
问题代码:
```
{vuln.code_snippet}
```

请生成修复后的安全代码。仅输出代码，不要解释。"""

        try:
            client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            response = client.chat.completions.create(
                model=self.config.ai_model,
                messages=[
                    {"role": "system", "content": "你是一个专业的安全工程师，输出仅包含修复代码。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=500,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"# 修复失败: {e}"

    def apply_fixes(self, vulns: List[Vulnerability], fixes: List[str]) -> int:
        """应用修复代码到源文件"""
        applied = 0
        for vuln, fix in zip(vulns, fixes):
            if not fix or fix.startswith('#'):
                continue

            try:
                lines = open(vuln.file, encoding='utf-8').readlines()
                if 0 <= vuln.line - 1 < len(lines):
                    lines[vuln.line - 1] = fix + '\n'
                    open(vuln.file, 'w', encoding='utf-8').writelines(lines)
                    applied += 1
            except Exception:
                pass

        return applied
