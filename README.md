[![CI](https://github.com/z13972509570-spec/ai-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/z13972509570-spec/ai-security-scanner/actions)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)

# 🔐 AI Security Scanner

> 基于 AST 静态分析 + AI 智能识别的代码安全漏洞扫描工具，自动检测 SQL注入、XSS、CSRF、认证缺陷等安全风险，并生成修复代码

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AST%20%2B%20AI-red.svg)]()

## ✨ 核心功能

- 🤖 **AI 漏洞识别**：基于 AST 静态分析 + LLM 深度语义分析
- 🔍 **多语言支持**：Python、JavaScript/TypeScript
- ⚡ **自动修复**：生成漏洞修复代码，一键应用
- 📊 **漏洞报告**：生成 HTML/JSON/Markdown 格式安全报告
- 🔄 **CI/CD 集成**：支持 GitHub Actions、GitLab CI
- 💻 **CLI + API**：命令行工具和 Python 库双模式

## 🛡️ 支持的漏洞类型

| 类型 | 说明 | 风险等级 |
|------|------|---------|
| SQL Injection | SQL 注入漏洞 | 🔴 严重 |
| XSS | 跨站脚本攻击 | 🔴 高危 |
| Command Injection | 命令注入 | 🔴 严重 |
| Path Traversal | 路径遍历 | 🟠 高危 |
| Hardcoded Secret | 硬编码密钥/密码 | 🔴 严重 |
| Weak Cryptography | 弱加密算法 | 🟠 中危 |
| Insecure Deserialization | 不安全反序列化 | 🔴 严重 |
| XXE | XML 外部实体注入 | 🔴 高危 |
| CSRF | 跨站请求伪造 | 🟠 中危 |
| IDOR | 越权访问 | 🔴 高危 |
| SSRF | 服务端请求伪造 | 🟠 高危 |
| Open Redirect | 开放重定向 | 🟡 中危 |
| YAML Deserialization | YAML 反序列化漏洞 | 🔴 高危 |

## 🚀 快速开始

### 安装

```bash
pip install ai-security-scanner
```

### CLI 扫描

```bash
# 扫描单个文件
ai-scan scan ./app.py

# 扫描目录
ai-scan scan ./src/

# 生成报告
ai-scan scan ./src/ --format html --output report.html

# 扫描并自动修复
ai-scan scan ./src/ --fix
```

### Python API

```python
from ai_security_scanner import SecurityScanner

scanner = SecurityScanner()
results = scanner.scan("./src")
for vuln in results.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.title}")
    print(f"  位置: {vuln.file}:{vuln.line}")
    print(f"  修复: {vuln.fix}")
```

## 📋 输出示例

```
🔐 AI Security Scanner v1.0.0
=============================

📁 扫描目录: ./src

✅ 发现漏洞 3 个

🔴 [CRITICAL] SQL Injection — src/api/user.py:42
   用户输入直接拼接到 SQL 语句中
   💡 修复: 使用参数化查询

🔴 [HIGH] Hardcoded Password — src/config.py:15
   发现硬编码数据库密码
   💡 修复: 使用环境变量

🟠 [MEDIUM] Insecure Cookie — src/app.py:88
   Cookie 未设置 secure 和 httponly 标志
   💡 修复: 添加安全标志
```

## ⚙️ 配置

```yaml
# .security-scan.yaml
rules:
  sql_injection: critical
  xss: high
  hardcoded_secret: critical
  weak_crypto: medium

ai:
  provider: openai  # openai | anthropic | ollama
  model: gpt-4o-mini
  auto_fix: true

output:
  format: html
  path: security-report.html
```

## 📄 License

MIT © 2026

---
版本: 1.0.0 | 许可证: MIT | 维护者: @z13972509570-spec
