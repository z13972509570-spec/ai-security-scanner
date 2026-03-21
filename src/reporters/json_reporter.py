"""JSON 报告生成器"""
import json
from pathlib import Path

class JSONReporter:
    def generate(self, result, output_path: str = "security-report.json"):
        data = result.to_dict()
        path = Path(output_path)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
        return path
