"""HTML 安全报告生成器"""
from pathlib import Path
from typing import List
from datetime import datetime
from jinja2 import Template
import json

from ..models import Vulnerability, Severity


class HTMLReporter:
    """生成交互式 HTML 安全报告"""

    TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 AI Security Scan Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0f172a; color: #e2e8f0; padding: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #f8fafc; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-bottom: 40px; }
        .stat { background: #1e293b; border-radius: 12px; padding: 24px; text-align: center; }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .stat-label { color: #94a3b8; margin-top: 8px; font-size: 0.9em; }
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #22c55e; }
        .vuln { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 16px;
                border-left: 4px solid; }
        .vuln.critical { border-color: #ef4444; }
        .vuln.high { border-color: #f97316; }
        .vuln.medium { border-color: #eab308; }
        .vuln.low { border-color: #22c55e; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .vuln-title { font-size: 1.1em; font-weight: 600; }
        .vuln-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }
        .badge-critical { background: #7f1d1d; color: #fca5a5; }
        .badge-high { background: #7c2d12; color: #fdba74; }
        .badge-medium { background: #713f12; color: #fde047; }
        .badge-low { background: #14532d; color: #86efac; }
        .vuln-meta { color: #94a3b8; font-size: 0.9em; margin-bottom: 12px; }
        .vuln-desc { color: #cbd5e1; margin-bottom: 16px; line-height: 1.6; }
        .code-block { background: #0f172a; border-radius: 8px; padding: 16px;
                      overflow-x: auto; margin-bottom: 16px; }
        .code-block code { color: #a5f3fc; font-family: 'Fira Code', monospace; font-size: 0.9em; }
        .fix-code { background: #022c22; border-radius: 8px; padding: 16px; margin-top: 12px; }
        .fix-code code { color: #86efac; font-family: 'Fira Code', monospace; }
        .cwe { color: #60a5fa; font-size: 0.85em; }
        footer { text-align: center; margin-top: 40px; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 AI Security Scan Report</h1>
        <p style="color:#94a3b8; margin-bottom:30px;">扫描时间: {{ scan_time }}</p>

        <div class="summary">
            <div class="stat">
                <div class="stat-value critical">{{ critical }}</div>
                <div class="stat-label">🔴 CRITICAL</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{{ high }}</div>
                <div class="stat-label">🟠 HIGH</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{{ medium }}</div>
                <div class="stat-label">🟡 MEDIUM</div>
            </div>
            <div class="stat">
                <div class="stat-value low">{{ low }}</div>
                <div class="stat-label">🟢 LOW</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ total }}</div>
                <div class="stat-label">📊 TOTAL</div>
            </div>
        </div>

        <div class="summary" style="grid-template-columns: repeat(3, 1fr);">
            <div class="stat">
                <div class="stat-value">{{ scanned_files }}</div>
                <div class="stat-label">📁 扫描文件</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ scanned_lines }}</div>
                <div class="stat-label">📝 扫描代码行</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ scan_duration }}s</div>
                <div class="stat-label">⏱️ 扫描耗时</div>
            </div>
        </div>

        <h2 style="margin: 30px 0 20px;">🐛 漏洞详情</h2>
        {% for vuln in vulnerabilities %}
        <div class="vuln {{ vuln.severity.lower() }}">
            <div class="vuln-header">
                <span class="vuln-title">{{ vuln.title }}</span>
                <span class="vuln-badge badge-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span>
            </div>
            <div class="vuln-meta">
                📍 {{ vuln.file }}:{{ vuln.line }}
                {% if vuln.cwe %}<span class="cwe"> · {{ vuln.cwe }}</span>{% endif %}
                {% if vuln.function %} · 函数: {{ vuln.function }}{% endif %}
            </div>
            <div class="vuln-desc">{{ vuln.description }}</div>
            {% if vuln.code_snippet %}
            <div class="code-block">
                <code>{{ vuln.code_snippet }}</code>
            </div>
            {% endif %}
            {% if vuln.fix_code %}
            <div class="fix-code">
                <strong>💡 修复代码:</strong><br>
                <code>{{ vuln.fix_code }}</code>
            </div>
            {% endif %}
        </div>
        {% endfor %}

        <footer>
            <p>🔐 AI Security Scanner v1.0.0 · Generated by AI Assistant</p>
        </footer>
    </div>
</body>
</html>
'''

    def generate(self, result, output_path: str = "security-report.html"):
        """生成 HTML 报告"""
        html = Template(self.TEMPLATE).render(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            critical=result.critical_count,
            high=result.high_count,
            medium=result.medium_count,
            low=result.low_count,
            total=result.total,
            scanned_files=result.scanned_files,
            scanned_lines=result.scanned_lines,
            scan_duration=f"{result.scan_time_seconds:.2f}",
            vulnerabilities=result.vulnerabilities,
        )

        path = Path(output_path)
        path.write_text(html, encoding='utf-8')
        return path
