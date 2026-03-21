"""AI 自动修复引擎"""
import os
import shutil
from pathlib import Path
from typing import List
from openai import OpenAI

from .models import Vulnerability


class AIFixEngine:
    """AI 驱动的漏洞自动修复引擎"""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.model = model

    def generate_fix(self, vuln: Vulnerability) -> str:
        """生成单个漏洞的修复代码"""
        prompt = f"""作为安全工程师，修复以下代码漏洞：

漏洞: {vuln.title}
描述: {vuln.description}
文件: {vuln.file}:{vuln.line}
代码:
```
{vuln.code_snippet}
```

输出格式要求：
1. 直接输出修复后的完整代码
2. 保持原有函数签名和逻辑结构
3. 仅修改存在漏洞的部分
4. 不要添加额外注释
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的安全工程师，只输出代码，不要解释。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=800,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"# AI 修复失败: {e}"

    def apply_fix(self, vuln: Vulnerability, fix_code: str) -> bool:
        """应用修复代码"""
        if not fix_code or fix_code.startswith('# AI'):
            return False

        try:
            file_path = Path(vuln.file)
            # 备份
            backup = file_path.with_suffix(file_path.suffix + '.bak')
            shutil.copy2(file_path, backup)

            # 读取文件
            lines = file_path.read_text(encoding='utf-8').splitlines()
            line_idx = vuln.line - 1

            if 0 <= line_idx < len(lines):
                lines[line_idx] = fix_code
                file_path.write_text('\n'.join(lines), encoding='utf-8')
                return True
        except Exception:
            pass
        return False

    def batch_fix(self, vulns: List[Vulnerability]) -> dict:
        """批量修复"""
        results = {"success": 0, "failed": 0, "skipped": 0}
        for vuln in vulns:
            fix = self.generate_fix(vuln)
            if self.apply_fix(vuln, fix):
                results["success"] += 1
            else:
                results["failed"] += 1
        return results
