# Semgrep Playground Backend

Semgrep Playground 的后端 API 服务，提供 semgrep 扫描功能。

## 功能特性

- **代码扫描**：接收 semgrep 规则和代码，返回扫描结果
- **规则验证**：验证 semgrep 规则的语法正确性
- **健康检查**：API 服务状态检查

## 快速开始

### 1. 安装依赖

```bash
# 使用 conda 环境（推荐）
conda activate api  # 或你的 Python 环境

# 安装依赖
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python app.py
```

服务将在 http://127.0.0.1:5000 启动。

### 3. 测试 API

#### 健康检查
```bash
curl http://127.0.0.1:5000/health
```

#### 扫描代码
```bash
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "rule": "rules:\n  - id: test-rule\n    languages: [java]\n    severity: ERROR\n    message: Test rule\n    pattern: \"$X + $Y\"",
    "code": "public class Test { String result = a + b; }"
  }'
```

#### 验证规则
```bash
curl -X POST http://127.0.0.1:5000/validate-rule \
  -H "Content-Type: application/json" \
  -d '{
    "rule": "rules:\n  - id: test\n    languages: [java]\n    pattern: test"
  }'
```

## API 接口

### POST /scan
扫描代码接口

**请求体：**
```json
{
  "rule": "yaml格式的semgrep规则",
  "code": "要扫描的代码",
  "language": "代码语言（可选，默认java）"
}
```

**响应：**
```json
{
  "success": true,
  "matches": [
    {
      "rule_id": "规则ID",
      "message": "匹配消息",
      "severity": "严重级别",
      "line_start": 开始行号,
      "line_end": 结束行号,
      "col_start": 开始列号,
      "col_end": 结束列号,
      "path": "文件路径",
      "code": "匹配的代码"
    }
  ],
  "message": "扫描结果消息"
}
```

### POST /validate-rule
验证规则语法

**请求体：**
```json
{
  "rule": "yaml格式的semgrep规则"
}
```

**响应：**
```json
{
  "valid": true,
  "message": "验证结果消息"
}
```

### GET /health
健康检查

**响应：**
```json
{
  "status": "ok",
  "message": "Semgrep Playground API is running"
}
```

## 环境要求

- Python 3.7+
- semgrep（需要在系统中安装）
- Flask 3.0.0
- Flask-CORS 4.0.0
- PyYAML 6.0.1

## 安装 Semgrep

```bash
# 使用 pip 安装
pip install semgrep

# 或使用 homebrew (macOS)
brew install semgrep

# 验证安装
semgrep --version
```