# 使用指南

## 快速开始

### 安装

```bash
pip install -e .
```

### 扫描代码

```bash
# 基本扫描
ai-scan scan ./src

# 生成 HTML 报告
ai-scan scan ./src --format html --output report.html

# 自动修复
ai-scan scan ./src --fix
```

### Python API

```python
from ai_security_scanner import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan("./src")

print(f"扫描完成: {result.scanned_files} 文件")
print(f"发现漏洞: {result.total} 个")

# 按严重等级分类
print(f"严重: {result.critical_count}")
print(f"高危: {result.high_count}")
```

## 支持的漏洞类型

| 类型 | CWE | 严重 |
|------|-----|------|
| SQL Injection | CWE-89 | CRITICAL |
| XSS | CWE-79 | HIGH |
| Command Injection | CWE-78 | CRITICAL |
| Path Traversal | CWE-22 | HIGH |
| Hardcoded Secret | CWE-798 | CRITICAL |
| Weak Crypto | CWE-327 | MEDIUM |
| Insecure Deserialization | CWE-502 | CRITICAL |
| XXE | CWE-611 | HIGH |
| CSRF | CWE-352 | MEDIUM |
| IDOR | CWE-639 | HIGH |
| SSRF | CWE-918 | HIGH |
| Open Redirect | CWE-601 | MEDIUM |

## 配置

### 配置文件

创建 `.security-scan.yaml`:

```yaml
rules:
  sql_injection: critical
  xss: high
  hardcoded_secret: critical

ai:
  provider: openai
  model: gpt-4o-mini
  auto_fix: true

output:
  format: html
  path: report.html
```

### 扫描选项

```python
scanner = SecurityScanner(
    rules={
        "sql_injection": "critical",
        "xss": "high"
    },
    ai_provider="openai",
    auto_fix=True
)
```

## 最佳实践

### 1. CI/CD 集成

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install ai-security-scanner
    ai-scan scan ./src --format json > scan-result.json
```

### 2. 排除目录

```python
result = scanner.scan(
    "./src",
    exclude=["tests/", "node_modules/", "vendor/"]
)
```

### 3. 指定语言

```python
result = scanner.scan("./src", language="python")
result = scanner.scan("./src", language="javascript")
```
