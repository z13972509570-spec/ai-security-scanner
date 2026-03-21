"""漏洞数据模型"""
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List


class Severity(str, Enum):
    """漏洞严重等级"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def emoji(self) -> str:
        emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }
        return emojis.get(self.value, "⚪")

    @property
    def cwe_id(self) -> str:
        cwe_map = {
            "CRITICAL": "CWE-89",   # SQL Injection
            "HIGH": "CWE-79",       # XSS
            "MEDIUM": "CWE-306",     # Missing Auth
            "LOW": "CWE-327",       # Weak Crypto
            "INFO": "CWE-703",       # Protection Failure
        }
        return cwe_map.get(self.value, "CWE-OTHER")


class Vulnerability(BaseModel):
    """单个漏洞"""
    id: str
    title: str
    description: str
    severity: Severity
    file: str
    line: int
    column: Optional[int] = None
    function: Optional[str] = None
    code_snippet: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix: Optional[str] = None
    fix_code: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    ai_confidence: float = Field(ge=0.0, le=1.0, default=0.9)

    @property
    def location(self) -> str:
        loc = f"{self.file}:{self.line}"
        if self.column:
            loc += f":{self.column}"
        return loc


class ScanResult(BaseModel):
    """扫描结果"""
    scanned_files: int = 0
    scanned_lines: int = 0
    scan_time_seconds: float = 0.0
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def total(self) -> int:
        return len(self.vulnerabilities)

    @property
    def is_secure(self) -> bool:
        return self.total == 0

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "scanned_lines": self.scanned_lines,
            "scan_time_seconds": self.scan_time_seconds,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": self.total,
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "location": v.location,
                    "description": v.description,
                    "fix": v.fix,
                    "fix_code": v.fix_code,
                    "cwe": v.cwe,
                    "owasp": v.owasp,
                }
                for v in self.vulnerabilities
            ],
        }
