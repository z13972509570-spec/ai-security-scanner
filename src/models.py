"""Security scanner models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Vulnerability data model"""
    file: str
    line: int
    title: str
    description: str
    severity: Severity
    code_snippet: str
    rule_id: Optional[str] = None
    confidence: float = 0.8
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "file": self.file,
            "line": self.line,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "code_snippet": self.code_snippet,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Scan result data model"""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scanned_files: int = 0
    scanned_lines: int = 0
    scan_time_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities by severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_count(self) -> int:
        """Get count of critical vulnerabilities"""
        return len(self.get_by_severity(Severity.CRITICAL))
    
    def get_high_count(self) -> int:
        """Get count of high severity vulnerabilities"""
        return len(self.get_by_severity(Severity.HIGH))
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scanned_files": self.scanned_files,
            "scanned_lines": self.scanned_lines,
            "scan_time_seconds": self.scan_time_seconds,
            "errors": self.errors,
            "summary": {
                "critical": self.get_critical_count(),
                "high": self.get_high_count(),
                "total": len(self.vulnerabilities),
            }
        }
