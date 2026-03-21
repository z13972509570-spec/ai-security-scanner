# API 文档

## SecurityScanner

主扫描器类。

### 构造函数

```python
SecurityScanner(
    rules: Optional[Dict] = None,
    ai_provider: str = "openai",
    auto_fix: bool = False
)
```

### 方法

#### `scan()`

扫描目标目录或文件。

```python
def scan(
    self,
    target: str,              # 目标路径
    language: str = "auto",   # 语言: auto/python/javascript
    recursive: bool = True
) -> ScanResult
```

**示例**:

```python
scanner = SecurityScanner()
result = scanner.scan("./src")

print(f"发现 {result.total} 个漏洞")
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.title}")
```

#### `scan_file()`

扫描单个文件。

```python
def scan_file(self, file_path: str) -> List[Vulnerability]
```

## ScanResult

扫描结果数据模型。

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `scanned_files` | int | 扫描文件数 |
| `scanned_lines` | int | 扫描代码行数 |
| `scan_time_seconds` | float | 扫描耗时 |
| `vulnerabilities` | List[Vulnerability] | 漏洞列表 |
| `errors` | List[str] | 错误列表 |
| `is_secure` | bool | 是否安全 |

### 统计属性

```python
result.critical_count  # 严重漏洞数
result.high_count      # 高危漏洞数
result.medium_count    # 中危漏洞数
result.low_count      # 低危漏洞数
result.total           # 总漏洞数
```

## Vulnerability

单个漏洞数据模型。

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `id` | str | 漏洞 ID |
| `title` | str | 漏洞标题 |
| `description` | str | 漏洞描述 |
| `severity` | Severity | 严重等级 |
| `file` | str | 文件路径 |
| `line` | int | 行号 |
| `code_snippet` | str | 问题代码 |
| `fix` | Optional[str] | 修复建议 |
| `fix_code` | Optional[str] | 修复代码 |
| `cwe` | Optional[str] | CWE 编号 |
| `owasp` | Optional[str] | OWASP 分类 |

## Severity

严重等级枚举。

```python
from ai_security_scanner import Severity

Severity.CRITICAL  # 严重
Severity.HIGH     # 高危
Severity.MEDIUM   # 中危
Severity.LOW      # 低危
Severity.INFO     # 信息
```

## CLI 命令

### scan

扫描代码。

```bash
ai-scan scan ./src
ai-scan scan ./src --format html --output report.html
ai-scan scan ./src --fix
```

### report

生成报告。

```bash
ai-scan report --format html
ai-scan report --format json
```
