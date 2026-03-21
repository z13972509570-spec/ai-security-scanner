#!/usr/bin/env python3
"""CLI 入口"""
import click
from pathlib import Path
from rich.console import Console

from src.ai_security_scanner import SecurityScanner
from src.reporters import HTMLReporter, JSONReporter, CLIReporter

console = Console()


@click.group()
@click.version_option("1.0.0")
def cli():
    """🔐 AI Security Scanner — AI-Powered Code Security Scanner"""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format",
              type=click.Choice(["html", "json", "cli"], case_sensitive=False),
              default="cli", help="输出格式")
@click.option("--output", "-o", default=None, help="输出文件路径")
@click.option("--fix", is_flag=True, help="自动生成并应用修复")
@click.option("--workers", "-w", default=4, help="并发扫描数")
def scan(path, output_format, output, fix, workers):
    """扫描代码目录/文件"""
    scanner = SecurityScanner()
    scanner.config.n_workers = workers

    console.print(f"🔐 开始扫描: {path}\n")
    result = scanner.scan(path)

    # 生成修复
    if fix and result.vulnerabilities:
        console.print("🤖 正在生成修复代码...")
        fixes = scanner.generate_fixes(result.vulnerabilities)
        applied = scanner.apply_fixes(result.vulnerabilities, fixes)
        console.print(f"✅ 已应用 {applied} 个修复")

    # 输出报告
    if output_format == "html":
        reporter = HTMLReporter()
        out_path = output or "security-report.html"
        reporter.generate(result, out_path)
        console.print(f"\n📄 HTML 报告已生成: {out_path}")
    elif output_format == "json":
        reporter = JSONReporter()
        out_path = output or "security-report.json"
        reporter.generate(result, out_path)
        console.print(f"\n📄 JSON 报告已生成: {out_path}")
    else:
        reporter = CLIReporter()
        reporter.report(result)


if __name__ == "__main__":
    cli()
