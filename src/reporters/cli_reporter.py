"""CLI 报告输出"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

class CLIReporter:
    def __init__(self):
        self.console = Console()

    def report(self, result):
        if result.is_secure:
            self.console.print("\n✅ [green]未发现安全漏洞！[/] 代码安全状态良好。\n")
            return

        # 摘要
        self.console.print(f"\n🔐 [bold]发现 {result.total} 个漏洞[/]\n")
        table = Table(show_header=True)
        table.add_column("等级", style="bold")
        table.add_column("数量")
        table.add_row("🔴 CRITICAL", str(result.critical_count))
        table.add_row("🟠 HIGH", str(result.high_count))
        table.add_row("🟡 MEDIUM", str(result.medium_count))
        table.add_row("🟢 LOW", str(result.low_count))
        self.console.print(table)

        # 漏洞列表
        for vuln in result.vulnerabilities:
            color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(vuln.severity, "white")

            self.console.print(f"\n{vuln.severity.emoji} [[{color}]{vuln.severity}[/]] {vuln.title}")
            self.console.print(f"   📍 {vuln.location}")
            self.console.print(f"   {vuln.description}")
            if vuln.code_snippet:
                syntax = Syntax(vuln.code_snippet, "python", theme="monokai")
                self.console.print(Panel(syntax, padding=(0, 1)))
