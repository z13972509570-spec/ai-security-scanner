# 配置说明

## 配置文件

位置: `.security-scan.yaml` 或 `pyproject.toml`

## 配置项

### rules

漏洞检测规则。

```yaml
rules:
  sql_injection: critical  # 启用，严重等级
  xss: high
  hardcoded_secret: critical
  weak_crypto: medium
  insecure_deserialization: critical
```

### ai

AI 修复配置。

```yaml
ai:
  provider: openai       # openai / anthropic / ollama
  model: gpt-4o-mini   # 模型名称
  auto_fix: true       # 是否自动修复
  api_key:             # 可选，从环境变量读取
```

### output

输出配置。

```yaml
output:
  format: html          # html / json / cli
  path: report.html    # 输出路径
  verbose: true        # 详细输出
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `OPENAI_API_KEY` | OpenAI API Key |
| `ANTHROPIC_API_KEY` | Anthropic API Key |
| `AI_SCAN_OUTPUT` | 默认输出目录 |
