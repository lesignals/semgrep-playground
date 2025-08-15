# 🔍 Semgrep 安全分析平台

一个现代化的 Semgrep 规则验证和代码安全分析平台，支持多编程语言的静态代码安全扫描。

## ✨ 特性

- 🎯 **实时代码扫描** - 基于 Semgrep 引擎的高精度安全漏洞检测
- 📝 **可视化规则编辑器** - 内置 Monaco Editor，支持 YAML 语法高亮和智能补全
- 💻 **多语言代码高亮** - 支持 Java、Python、JavaScript、TypeScript、Go、PHP、Rust、Scala、HTML 等
- 🗂️ **规则分类管理** - 按安全类型和编程语言自动分类管理规则
- ➕ **手动规则创建** - 通过图形界面快速创建自定义安全规则
- 🔄 **动态规则加载** - 支持文件系统规则热重载
- 🎨 **现代化界面** - 基于 Next.js 15 和 Tailwind CSS 的响应式设计
- 🚀 **高级扫描支持** - 集成 Semgrep Pro 功能，支持污点分析等高级检测

## 🏗️ 技术架构

### 前端技术栈
- **Next.js 15** - React 全栈框架
- **TypeScript** - 类型安全的 JavaScript
- **Monaco Editor** - VS Code 核心编辑器
- **Tailwind CSS** - 实用优先的 CSS 框架
- **Lucide React** - 现代图标库

### 后端技术栈
- **Flask** - 轻量级 Python Web 框架
- **Semgrep** - 静态代码分析引擎
- **Flask-CORS** - 跨域资源共享支持
- **PyYAML** - YAML 解析库

## 🚀 快速开始

### 环境要求

- Node.js 18+
- Python 3.8+
- Semgrep CLI 工具

### 安装步骤

1. **克隆项目**
```bash
git clone https://github.com/lesignals/semgrep-playground.git
cd semgrep-playground
```

2. **安装 Semgrep**
```bash
# 使用 pip 安装
pip install semgrep

# 或使用 Homebrew (macOS)
brew install semgrep

# 验证安装
semgrep --version
```

3. **启动后端服务**
```bash
cd backend
pip install -r requirements.txt
python app.py
```

4. **启动前端服务**
```bash
cd semgrep-playground
npm install
npm run dev
```

5. **访问应用**
```
前端: http://localhost:3000
后端API: http://127.0.0.1:5000
```

## 📖 使用指南

### 基本操作

1. **选择安全规则** - 在左侧规则库中选择或创建规则
2. **编辑代码** - 在右侧编辑器中输入或修改测试代码  
3. **运行扫描** - 点击 "Run" 按钮执行安全扫描
4. **查看结果** - 在结果面板查看检测到的安全问题

### 创建自定义规则

1. 点击 "新建规则" 按钮
2. 填写规则名称、分类和编程语言
3. 编辑 YAML 规则配置
4. 编写测试代码示例
5. 保存规则到文件系统

### 支持的安全检测类型

- **SQL 注入** (CWE-89) - 检测 SQL 查询字符串拼接漏洞
- **跨站脚本攻击** (CWE-79) - 识别未转义的用户输入输出
- **弱加密算法** (CWE-327) - 发现过时的加密方法使用
- **硬编码凭据** (CWE-798) - 检测源码中的敏感信息
- **命令注入** (CWE-78) - 识别危险的系统调用
- **原型污染** (CWE-1321) - JavaScript 对象属性污染
- **代码注入** (CWE-94) - Python eval/exec 危险用法

## 📁 项目结构

```
semgrep-playground/
├── components/                 # React 组件
│   └── simple-semgrep-interface.tsx
├── app/                       # Next.js 应用路由
├── public/                    # 静态资源
└── package.json              # 前端依赖

backend/
├── app.py                    # Flask 应用主文件
├── rules/                    # 规则文件存储
│   ├── java-security/        # Java 安全规则
│   ├── python-security/      # Python 安全规则
│   ├── javascript-security/  # JavaScript 安全规则
│   └── go/                   # Go 安全规则
├── test-code/               # 测试代码示例
└── requirements.txt         # Python 依赖
```

## 🔧 API 文档

### 扫描接口
```http
POST /scan
Content-Type: application/json

{
  "rule": "YAML格式的Semgrep规则",
  "code": "要扫描的源代码",
  "language": "编程语言(可选)"
}
```

### 规则管理接口
```http
# 获取规则列表
GET /rules

# 获取规则内容
GET /rule/{rule_id}

# 创建新规则
POST /create-rule

# 删除规则
DELETE /rule/{rule_id}
```

## 🛠️ 开发指南

### 添加新的安全规则

1. 在 `backend/rules/{category}/` 下创建 YAML 规则文件
2. 在 `backend/test-code/` 下添加对应的测试代码
3. 重启服务，规则会自动加载到界面

### 扩展编程语言支持

1. 在前端组件中添加语言检测逻辑
2. 在后端添加文件扩展名映射
3. 创建对应语言的规则模板

### 规则文件格式

```yaml
rules:
  - id: unique-rule-identifier
    languages:
      - target-language
    severity: ERROR|WARNING|INFO
    message: "漏洞描述信息"
    metadata:
      category: security
      confidence: HIGH|MEDIUM|LOW
      impact: HIGH|MEDIUM|LOW
      cwe: "CWE编号和描述"
      owasp: "OWASP分类"
    patterns:
      - pattern-either:
          - pattern: |
              匹配模式1
          - pattern: |
              匹配模式2
```

## 🤝 贡献指南

欢迎提交问题报告和功能请求！

1. Fork 项目仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🎯 路线图

- [ ] 添加更多编程语言支持 (C/C++, C#, Ruby)
- [ ] 集成 CI/CD 工具支持
- [ ] 添加规则性能分析
- [ ] 支持批量文件扫描
- [ ] 添加扫描报告导出功能
- [ ] 实现规则共享和导入功能

## 📞 联系方式

- 项目主页: https://github.com/lesignals/semgrep-playground
- 问题报告: https://github.com/lesignals/semgrep-playground/issues

---

⚡ **让代码安全变得简单直观！** 通过 Semgrep 安全分析平台，快速识别和修复代码中的安全漏洞。