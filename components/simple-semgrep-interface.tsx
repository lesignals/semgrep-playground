"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Play, ChevronRight, ChevronDown, Search, Folder, FolderOpen, Loader, Plus, Save, X, Trash2 } from "lucide-react"
import Editor from '@monaco-editor/react'

const defaultRule = `rules:
  - id: sql-injection-detection
    languages:
      - java
    severity: ERROR
    message: "潜在的 SQL 注入漏洞：直接拼接用户输入到 SQL 查询中"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-89: SQL 注入"
      owasp: "A03:2021 - 注入"
    patterns:
      - pattern-either:
          - pattern: |
              String $SQL = "..." + $USER_INPUT + "...";
          - pattern: |
              String $SQL = "..." + $OBJ.getParameter(...) + "...";
          - pattern: |
              Statement $STMT = ...;
              ...
              $STMT.executeQuery("..." + $VAR + "...");
          - pattern: |
              PreparedStatement $STMT = ...;
              ...
              $STMT.executeQuery("..." + $VAR + "...");`

const defaultCode = `package org.example.security;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnerableCode {
    
    // 漏洞1：直接字符串拼接 SQL 注入
    public void vulnerableQuery1(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
    
    // 漏洞2：使用 PreparedStatement 但仍然字符串拼接
    public void vulnerableQuery2(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        PreparedStatement pstmt = conn.prepareStatement(query);
        ResultSet rs = pstmt.executeQuery();
    }
    
    // 漏洞3：动态构建 SQL 查询
    public void vulnerableQuery3(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        
        String dynamicSql = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
        ResultSet rs = stmt.executeQuery(dynamicSql);
    }
    
    // 安全示例：使用参数化查询
    public void safeQuery(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
    }
}`

interface RuleCategory {
  name: string
  count: number
  expanded: boolean
  rules?: Array<{
    id: string
    name: string
    category: string
  }>
}

const YamlHighlighter = ({ content, onChange }: { content: string; onChange: (value: string) => void }) => {
  return (
    <div className="h-full min-h-96">
      <Editor
        height="100%"
        defaultLanguage="yaml"
        value={content}
        onChange={(value) => onChange(value || '')}
        theme="vs"
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          wordWrap: 'on',
          folding: true,
          lineDecorationsWidth: 10,
          lineNumbersMinChars: 3,
          renderLineHighlight: 'line',
          selectOnLineNumbers: true,
        }}
      />
    </div>
  )
}

const CodeHighlighter = ({ content, highlightedLines, onChange, language }: { 
  content: string; 
  highlightedLines: number[]; 
  onChange?: (value: string) => void;
  language?: string;
}) => {
  const [editor, setEditor] = useState<any>(null)
  const [decorationIds, setDecorationIds] = useState<string[]>([])
  const [stylesAdded, setStylesAdded] = useState(false)
  
  // 检测代码语言
  const detectLanguage = (code: string): string => {
    if (language) return language
    
    // 优先级更高的检测
    if (code.includes('def ') && (code.includes('pass') || code.includes('import') || code.includes('#') || /^\s*#/.test(code))) return 'python'
    if (code.includes('<?php') || code.includes('$_') || code.includes('function ') && code.includes('$')) return 'php'
    if (code.includes('package ') && code.includes('import ') && (code.includes('public ') || code.includes('class ') || code.includes('void '))) return 'java'
    if (code.includes('fn ') && (code.includes('let ') || code.includes('mut ') || code.includes('&str'))) return 'rust'
    if (code.includes('func ') && code.includes('package ') && (code.includes('http.Request') || code.includes('fmt.') || code.includes('import ('))) return 'go'
    if (code.includes('object ') && code.includes('def ') && code.includes('scala')) return 'scala'
    if (code.includes('interface ') && code.includes('type ') || code.includes(': string') || code.includes(': number')) return 'typescript'
    if (code.includes('#include') || code.includes('int main') || code.includes('std::')) return 'cpp'
    if (code.includes('<html') || code.includes('<div') || code.includes('<body') || code.includes('<!DOCTYPE')) return 'html'
    if (code.includes('function ') || code.includes('const ') || code.includes('let ') || code.includes('=>')) return 'javascript'
    
    // 基于文件内容特征的检测
    const lines = code.split('\n').filter(line => line.trim())
    if (lines.length > 0) {
      const firstLine = lines[0]
      if (firstLine.startsWith('package main') || firstLine.startsWith('package ')) {
        // 进一步检查是否为Go（不是Java）
        if (code.includes('func ') || code.includes('import (')) return 'go'
        if (code.includes('public class') || code.includes('import java')) return 'java'
      }
      if (firstLine.startsWith('#') && lines.some(line => line.includes('def '))) return 'python'
      if (firstLine.includes('<?php')) return 'php'
      if (firstLine.includes('<!DOCTYPE') || firstLine.includes('<html')) return 'html'
    }
    
    return 'plaintext' // 默认为纯文本
  }

  const handleEditorDidMount = (editorInstance: any) => {
    setEditor(editorInstance)
  }

  // 添加样式（只添加一次）
  useEffect(() => {
    if (!stylesAdded) {
      const style = document.createElement('style')
      style.id = 'semgrep-highlight-styles'
      style.textContent = `
        .highlighted-line {
          background-color: rgba(255, 0, 0, 0.1) !important;
          border-left: 4px solid #ef4444 !important;
        }
        .highlighted-glyph {
          background-color: #ef4444 !important;
          width: 4px !important;
        }
      `
      
      // 检查是否已存在样式，避免重复添加
      const existingStyle = document.getElementById('semgrep-highlight-styles')
      if (!existingStyle) {
        document.head.appendChild(style)
      }
      setStylesAdded(true)
    }
  }, [stylesAdded])

  // 更新高亮行装饰
  useEffect(() => {
    if (editor) {
      // 导入 Monaco Editor 的类型
      import('monaco-editor').then((monaco) => {
        // 强制清除所有装饰，包括可能遗留的装饰
        const allDecorations = editor.getModel()?.getAllDecorations() || []
        const currentDecorationIds = allDecorations
          .filter(decoration => 
            decoration.options.className === 'highlighted-line' || 
            decoration.options.glyphMarginClassName === 'highlighted-glyph'
          )
          .map(decoration => decoration.id)
        
        if (currentDecorationIds.length > 0) {
          editor.deltaDecorations(currentDecorationIds, [])
        }
        
        // 也清除我们记录的装饰ID
        if (decorationIds.length > 0) {
          editor.deltaDecorations(decorationIds, [])
        }
        
        // 如果有新的高亮行，创建新装饰
        if (highlightedLines.length > 0) {
          const decorations = highlightedLines.map(lineNumber => ({
            range: new monaco.Range(lineNumber, 1, lineNumber, 1),
            options: {
              isWholeLine: true,
              className: 'highlighted-line',
              glyphMarginClassName: 'highlighted-glyph'
            }
          }))
          
          // 应用新装饰并保存装饰ID
          const newDecorationIds = editor.deltaDecorations([], decorations)
          setDecorationIds(newDecorationIds)
        } else {
          setDecorationIds([])
        }
      })
    }
  }, [editor, highlightedLines])

  const detectedLanguage = detectLanguage(content)

  return (
    <div className="h-full min-h-96">
      <Editor
        height="100%"
        language={detectedLanguage} // 使用 language 而不是 defaultLanguage
        value={content}
        onChange={onChange ? (value) => onChange(value || '') : undefined}
        onMount={handleEditorDidMount}
        theme="vs"
        options={{
          readOnly: !onChange,
          minimap: { enabled: false },
          fontSize: 14,
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          wordWrap: 'on',
          folding: true,
          lineDecorationsWidth: 10,
          lineNumbersMinChars: 3,
          renderLineHighlight: 'line',
          selectOnLineNumbers: true,
          glyphMargin: true,
          overviewRulerBorder: false,
          hideCursorInOverviewRuler: true,
          overviewRulerLanes: 0,
          disableLayerHinting: true,
          fixedOverflowWidgets: true,
        }}
        path={undefined} // 不设置路径，避免显示文件名
      />
    </div>
  )
}

interface SemgrepMatch {
  rule_id: string
  message: string
  severity: string
  line_start: number
  line_end: number
  col_start: number
  col_end: number
  path: string
  code: string
}

export function SimpleSemgrepInterface() {
  const [ruleContent, setRuleContent] = useState(defaultRule)
  const [codeContent, setCodeContent] = useState(defaultCode)
  const [highlightedLines, setHighlightedLines] = useState<number[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [categories, setCategories] = useState<RuleCategory[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [scanResults, setScanResults] = useState<SemgrepMatch[]>([])
  const [showResults, setShowResults] = useState(false)
  const [isLoadingRules, setIsLoadingRules] = useState(true)
  const [isCreatingRule, setIsCreatingRule] = useState(false)
  const [newRuleData, setNewRuleData] = useState({
    name: '',
    category: '',
    language: 'java'
  })
  const [deleteConfirm, setDeleteConfirm] = useState<{
    show: boolean,
    ruleId: string,
    ruleName: string
  }>({
    show: false,
    ruleId: '',
    ruleName: ''
  })
  const [isDeleting, setIsDeleting] = useState(false)
  
  // 解析规则 ID
  const getRuleId = () => {
    try {
      const yamlContent = ruleContent
      const match = yamlContent.match(/^\s*-\s*id:\s*(.+)$/m)
      return match ? match[1].trim() : 'unknown-rule'
    } catch {
      return 'unknown-rule'
    }
  }
  
  // 解析代码文件名（直接从规则语言获取）
  const getCodeFileName = () => {
    try {
      // 从规则内容中提取语言
      const languageMatch = ruleContent.match(/languages:\s*\n\s*-\s*(\w+)/)
      const ruleLanguage = languageMatch ? languageMatch[1] : null
      
      // 从规则ID获取规则名称
      const ruleId = getRuleId()
      const parts = ruleId.split('.')
      const ruleName = parts.length > 1 ? parts[parts.length - 1] : 'TestCode'
      
      // 根据规则语言设置文件扩展名
      const getExtension = (lang: string): string => {
        const extensions: { [key: string]: string } = {
          'java': 'java',
          'python': 'py', 
          'javascript': 'js',
          'typescript': 'ts',
          'go': 'go',
          'php': 'php',
          'rust': 'rs',
          'scala': 'scala',
          'html': 'html',
          'cpp': 'cpp'
        }
        return extensions[lang] || 'txt'
      }
      
      if (ruleLanguage) {
        const extension = getExtension(ruleLanguage)
        return `${ruleName}.${extension}`
      }
      
      // 后备方案：使用默认扩展名
      return `${ruleName}.java`
    } catch {
      return 'TestCode.java'
    }
  }
  
  // 加载真实的 Semgrep 规则
  useEffect(() => {
    const loadRules = async () => {
      try {
        const response = await fetch('http://127.0.0.1:5000/rules')
        const result = await response.json()
        
        if (result.success && result.categories) {
          const formattedCategories: RuleCategory[] = Object.entries(result.categories).map(([name, rules]: [string, any]) => ({
            name,
            count: rules.length,
            expanded: name === 'java', // 默认展开 java 分类
            rules: rules
          }))
          
          setCategories(formattedCategories)
        } else {
          console.warn('无法加载 Semgrep 规则，使用默认示例')
          // 使用备用的示例数据
          setCategories([
            { name: "示例规则", count: 1, expanded: true, rules: [{ id: "sql-injection-detection", name: "SQL注入检测", category: "示例规则" }] }
          ])
        }
      } catch (error) {
        console.warn('加载规则失败，使用默认示例:', error)
        setCategories([
          { name: "示例规则", count: 1, expanded: true, rules: [{ id: "sql-injection-detection", name: "SQL注入检测", category: "示例规则" }] }
        ])
      } finally {
        setIsLoadingRules(false)
      }
    }
    
    loadRules()
  }, [])
  
  // 加载特定规则内容
  const loadRuleContent = async (ruleId: string) => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/rule/${encodeURIComponent(ruleId)}`)
      const result = await response.json()
      
      if (result.success && result.content) {
        setRuleContent(result.content)
        
        // 优先使用服务器返回的测试代码，否则使用本地生成的
        if (result.test_code) {
          setCodeContent(result.test_code)
        } else {
          const testCode = getTestCodeForRule(ruleId)
          if (testCode) {
            setCodeContent(testCode)
          }
        }
        
        // 清空之前的扫描结果
        setHighlightedLines([])
        setScanResults([])
        setShowResults(false)
      } else {
        console.error('加载规则内容失败:', result.error)
      }
    } catch (error) {
      console.error('加载规则内容失败:', error)
    }
  }
  
  // 创建新规则的模板
  const createNewRuleTemplate = (name: string, category: string, language: string): string => {
    const ruleId = `${category.toLowerCase().replace(/\s+/g, '-')}.${name}`
    return `rules:
  - id: ${ruleId}
    languages:
      - ${language}
    severity: ERROR
    message: "TODO: 添加规则描述"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-XXX: TODO"
      owasp: "TODO: OWASP分类"
    patterns:
      - pattern: |
          TODO: 添加匹配模式
`
  }

  // 创建新测试代码的模板
  const createNewCodeTemplate = (language: string): string => {
    const templates: { [key: string]: string } = {
      java: `package org.example.security;

public class NewRuleExample {
    
    // TODO: 添加漏洞代码示例
    public void vulnerableMethod() {
        // 在这里添加会被规则检测到的代码
    }
    
    // TODO: 添加安全代码示例
    public void safeMethod() {
        // 在这里添加安全的代码实现
    }
}`,
      python: `# TODO: 添加漏洞代码示例
def vulnerable_function():
    # 在这里添加会被规则检测到的代码
    pass

# TODO: 添加安全代码示例  
def safe_function():
    # 在这里添加安全的代码实现
    pass`,
      javascript: `// TODO: 添加漏洞代码示例
function vulnerableFunction() {
    // 在这里添加会被规则检测到的代码
}

// TODO: 添加安全代码示例
function safeFunction() {
    // 在这里添加安全的代码实现
}`,
      typescript: `// TODO: 添加漏洞代码示例
function vulnerableFunction(input: string): string {
    // 在这里添加会被规则检测到的代码
    return input;
}

// TODO: 添加安全代码示例
function safeFunction(input: string): string {
    // 在这里添加安全的代码实现
    return input;
}`,
      go: `package main

import "fmt"

// TODO: 添加漏洞代码示例
func vulnerableFunction(input string) string {
    // 在这里添加会被规则检测到的代码
    return input
}

// TODO: 添加安全代码示例
func safeFunction(input string) string {
    // 在这里添加安全的代码实现
    return input
}`,
      php: `<?php
// TODO: 添加漏洞代码示例
function vulnerableFunction($input) {
    // 在这里添加会被规则检测到的代码
    return $input;
}

// TODO: 添加安全代码示例
function safeFunction($input) {
    // 在这里添加安全的代码实现
    return $input;
}
?>`,
      rust: `// TODO: 添加漏洞代码示例
fn vulnerable_function(input: &str) -> String {
    // 在这里添加会被规则检测到的代码
    input.to_string()
}

// TODO: 添加安全代码示例
fn safe_function(input: &str) -> String {
    // 在这里添加安全的代码实现
    input.to_string()
}`,
      scala: `object NewRuleExample {
  // TODO: 添加漏洞代码示例
  def vulnerableFunction(input: String): String = {
    // 在这里添加会被规则检测到的代码
    input
  }
  
  // TODO: 添加安全代码示例
  def safeFunction(input: String): String = {
    // 在这里添加安全的代码实现
    input
  }
}`,
      html: `<!DOCTYPE html>
<html>
<head>
    <title>Security Example</title>
</head>
<body>
    <!-- TODO: 添加漏洞代码示例 -->
    <div id="vulnerable">
        <!-- 在这里添加会被规则检测到的HTML -->
    </div>
    
    <!-- TODO: 添加安全代码示例 -->
    <div id="safe">
        <!-- 在这里添加安全的HTML实现 -->
    </div>
</body>
</html>`
    }
    return templates[language] || templates.java
  }

  // 开始创建新规则
  const startCreateNewRule = () => {
    setIsCreatingRule(true)
    setRuleContent(createNewRuleTemplate('new-rule', 'Custom Rules', 'java'))
    setCodeContent(createNewCodeTemplate('java'))
    setHighlightedLines([])
    setScanResults([])
    setShowResults(false)
  }

  // 取消创建新规则
  const cancelCreateNewRule = () => {
    setIsCreatingRule(false)
    setNewRuleData({ name: '', category: '', language: 'java' })
    setHighlightedLines([])
    setScanResults([])
    setShowResults(false)
  }

  // 保存新规则
  const saveNewRule = async () => {
    if (!newRuleData.name || !newRuleData.category) {
      alert('请填写规则名称和分类')
      return
    }

    try {
      const response = await fetch('http://127.0.0.1:5000/create-rule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: newRuleData.name,
          category: newRuleData.category,
          language: newRuleData.language,
          rule_content: ruleContent,
          test_code: codeContent
        })
      })

      const result = await response.json()
      
      if (result.success) {
        alert('规则创建成功！')
        setIsCreatingRule(false)
        setNewRuleData({ name: '', category: '', language: 'java' })
        // 重新加载规则列表
        window.location.reload()
      } else {
        alert(`创建失败: ${result.error}`)
      }
    } catch (error) {
      console.error('创建规则失败:', error)
      alert('创建规则失败，请检查网络连接')
    }
  }

  // 显示删除确认对话框
  const showDeleteConfirm = (ruleId: string, ruleName: string) => {
    setDeleteConfirm({
      show: true,
      ruleId,
      ruleName
    })
  }

  // 取消删除
  const cancelDelete = () => {
    setDeleteConfirm({
      show: false,
      ruleId: '',
      ruleName: ''
    })
  }

  // 确认删除规则
  const confirmDeleteRule = async () => {
    if (!deleteConfirm.ruleId) return

    setIsDeleting(true)
    try {
      const response = await fetch(`http://127.0.0.1:5000/rule/${encodeURIComponent(deleteConfirm.ruleId)}`, {
        method: 'DELETE'
      })

      const result = await response.json()
      
      if (result.success) {
        alert('规则删除成功！')
        // 取消删除对话框
        cancelDelete()
        // 重新加载规则列表
        window.location.reload()
      } else {
        alert(`删除失败: ${result.error}`)
      }
    } catch (error) {
      console.error('删除规则失败:', error)
      alert('删除规则失败，请检查网络连接')
    } finally {
      setIsDeleting(false)
    }
  }

  // 根据规则 ID 获取对应的测试代码
  const getTestCodeForRule = (ruleId: string): string => {
    const codeExamples: { [key: string]: string } = {
      // Example Rules
      'sql-injection-detection': `package org.example.security;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SQLInjectionExample {
    
    // Vulnerable: Direct string concatenation
    public void vulnerableQuery1(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
    
    // Vulnerable: Even with PreparedStatement but still concatenating
    public void vulnerableQuery2(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        PreparedStatement pstmt = conn.prepareStatement(query);
        ResultSet rs = pstmt.executeQuery();
    }
    
    // Safe: Using parameterized query
    public void safeQuery(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
    }
}`,

      // Java Security Rules
      'java.lang.security.audit.sqli': `package org.example.security;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SQLInjectionVulnerable {
    
    // Vulnerable: String concatenation with executeQuery
    public void vulnerableQuery1(HttpServletRequest request) throws SQLException {
        String userInput = request.getParameter("input");
        String sql = "SELECT * FROM table WHERE column = '" + userInput + "'";
        
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
    
    // Vulnerable: String concatenation with execute
    public void vulnerableQuery2(String userInput) throws SQLException {
        String sql = "UPDATE users SET status = '" + userInput + "'";
        
        Statement stmt = connection.createStatement();
        stmt.execute(sql);
    }
    
    // Vulnerable: Direct concatenation in executeQuery call
    public void vulnerableQuery3(String userInput) throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.executeQuery("SELECT * FROM products WHERE name = '" + userInput + "'");
    }
    
    // Safe: Using prepared statements
    public void safeQuery(String userInput) throws SQLException {
        String sql = "SELECT * FROM table WHERE column = ?";
        PreparedStatement pstmt = connection.prepareStatement(sql);
        pstmt.setString(1, userInput);
        ResultSet rs = pstmt.executeQuery();
    }
}`,

      'java.lang.security.audit.xss': `package org.example.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class XSSVulnerable {
    
    // Vulnerable: Direct output with println
    public void vulnerableOutput1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + userInput + "</h1>");
    }
    
    // Vulnerable: Direct output with print
    public void vulnerableOutput2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.print("<div>Welcome " + name + "</div>");
    }
    
    // Vulnerable: Direct output with write
    public void vulnerableOutput3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data = request.getParameter("data");
        PrintWriter out = response.getWriter();
        out.write("<script>var data = '" + data + "';</script>");
    }
    
    // Vulnerable: Response writer direct output
    public void vulnerableOutput4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String content = request.getParameter("content");
        response.getWriter().println("<p>" + content + "</p>");
    }
    
    // Safe: Escaped output
    public void safeOutput(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        String escaped = escapeHtml(userInput);
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + escaped + "</h1>");
    }
    
    private String escapeHtml(String input) {
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}`,

      'java.lang.security.audit.crypto': `package org.example.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.MessageDigest;

public class WeakCryptoVulnerable {
    
    // Vulnerable: Using DES key generator
    public void weakKeyGeneration1() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        // DES is weak encryption
    }
    
    // Vulnerable: Using DES cipher
    public void weakCipher1() throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        // DES encryption is vulnerable
    }
    
    // Vulnerable: Using MD5 hash
    public void weakHash1(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(data.getBytes());
        // MD5 is cryptographically broken
    }
    
    // Vulnerable: Using SHA1 hash
    public void weakHash2(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] hash = md.digest(data.getBytes());
        // SHA1 is vulnerable to collision attacks
    }
    
    // Vulnerable: Using SHA-1 with hyphen
    public void weakHash3(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(data.getBytes());
    }
    
    // Safe: Using AES
    public void strongCrypto() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}`,

      'java.lang.security.audit.hardcoded-secret': `package org.example.security;

public class HardcodedSecretsVulnerable {
    
    // Vulnerable: Hardcoded password
    public void connectDatabase1() {
        String password = "mySecretPassword123";
        // Never hardcode passwords
    }
    
    // Vulnerable: Hardcoded API key
    public void callAPI1() {
        String apiKey = "sk-1234567890abcdef";
        // API keys should not be hardcoded
    }
    
    // Vulnerable: Hardcoded secret
    public void encryptData1() {
        String secret = "myEncryptionSecret456";
        // Secrets should be externalized
    }
    
    // Vulnerable: Various hardcoded credentials
    public void multipleSecrets() {
        String dbPassword = "admin123456";
        String jwtSecret = "myJWTSecretKey789";
        String encryptionKey = "encryptionKey123";
        String accessToken = "token_abcdef123456";
    }
    
    // Safe: Using environment variables
    public void safeCredentials() {
        String password = System.getenv("DB_PASSWORD");
        String apiKey = System.getProperty("api.key");
        String secret = loadFromConfig("encryption.secret");
    }
    
    private String loadFromConfig(String key) {
        // Load from external configuration
        return null;
    }
}`,

      // JavaScript Security Rules
      'javascript.lang.security.audit.sqli': `// JavaScript SQL Injection Examples

const mysql = require('mysql');
const express = require('express');

// Vulnerable: Direct concatenation in query
function vulnerableQuery1(userId) {
    const connection = mysql.createConnection(config);
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    connection.query(query, (error, results) => {
        // Process results
    });
}

// Vulnerable: Template literal injection
function vulnerableQuery2(username) {
    const db = getDatabase();
    db.query(\`SELECT * FROM users WHERE username = '\${username}'\`);
}

// Vulnerable: String concatenation with execute
function vulnerableQuery3(userInput) {
    const conn = getConnection();
    conn.execute("SELECT * FROM products WHERE name = '" + userInput + "'");
}

// Safe: Using parameterized queries
function safeQuery(userId) {
    const connection = mysql.createConnection(config);
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [userId], (error, results) => {
        // Process results safely
    });
}`,

      'javascript.lang.security.audit.xss': `// JavaScript XSS Vulnerability Examples

// Vulnerable: Direct innerHTML assignment
function vulnerableOutput1(userInput) {
    const element = document.getElementById('content');
    element.innerHTML = userInput;
    // User input directly inserted into DOM
}

// Vulnerable: document.write with user input
function vulnerableOutput2(userInput) {
    document.write('<div>' + userInput + '</div>');
    // Dangerous document.write usage
}

// Vulnerable: outerHTML assignment
function vulnerableOutput3(userInput) {
    const element = document.querySelector('.message');
    element.outerHTML = '<p>' + userInput + '</p>';
}

// Vulnerable: jQuery html() method
function vulnerableOutput4(userInput) {
    $('#message').html(userInput);
    // jQuery html() can execute scripts
}

// Safe: Using textContent
function safeOutput1(userInput) {
    const element = document.getElementById('content');
    element.textContent = userInput;
    // Text content doesn't execute scripts
}

// Safe: Proper escaping
function safeOutput2(userInput) {
    const escaped = escapeHtml(userInput);
    element.innerHTML = escaped;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}`,

      'javascript.lang.security.audit.dangerous-object-assign': `// JavaScript Prototype Pollution Examples

const _ = require('lodash');
const $ = require('jquery');

// Vulnerable: Object.assign with user input
function vulnerableAssign1(userInput) {
    const target = {};
    Object.assign(target, userInput);
    // Can pollute Object.prototype
}

// Vulnerable: Lodash merge
function vulnerableAssign2(userInput) {
    const target = {};
    _.merge(target, userInput);
    // Lodash merge is vulnerable to prototype pollution
}

// Vulnerable: jQuery extend
function vulnerableAssign3(userInput) {
    const target = {};
    $.extend(target, userInput);
    // jQuery extend can cause prototype pollution
}

// Safe: Object.assign with null prototype
function safeAssign1(userInput) {
    const target = Object.create(null);
    Object.assign(target, userInput);
    // Null prototype prevents pollution
}

// Safe: Property validation
function safeAssign2(userInput) {
    const target = {};
    for (const key in userInput) {
        if (userInput.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor') {
            target[key] = userInput[key];
        }
    }
}`,

      // Python Security Rules
      'python.lang.security.audit.sqli': `# Python SQL Injection Examples

import sqlite3
import mysql.connector

# Vulnerable: String concatenation
def vulnerable_query1(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

# Vulnerable: f-string injection
def vulnerable_query2(username):
    conn = mysql.connector.connect(host='localhost', database='test')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()

# Vulnerable: % formatting
def vulnerable_query3(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '%s'" % user_input)
    return cursor.fetchall()

# Vulnerable: .format() injection
def vulnerable_query4(category):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE category = '{}'".format(category))
    return cursor.fetchall()

# Safe: Parameterized query
def safe_query(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()`,

      'python.lang.security.audit.code-injection': `# Python Code Injection Examples

# Vulnerable: eval() with user input
def vulnerable_eval(user_input):
    result = eval(user_input)
    # eval can execute arbitrary Python code
    return result

# Vulnerable: exec() with user input
def vulnerable_exec(user_code):
    exec(user_code)
    # exec can execute arbitrary Python code

# Vulnerable: compile() with user input
def vulnerable_compile(user_input):
    code_obj = compile(user_input, '<string>', 'exec')
    exec(code_obj)

# Safe: Using ast.literal_eval for safe evaluation
import ast

def safe_eval(user_input):
    try:
        result = ast.literal_eval(user_input)
        # Only evaluates literals safely
        return result
    except (ValueError, SyntaxError):
        return None

# Safe: Input validation and sanitization
def safe_calculation(expression):
    # Validate that expression only contains safe characters
    allowed_chars = set('0123456789+-*/(). ')
    if all(c in allowed_chars for c in expression):
        try:
            return eval(expression)
        except:
            return None
    return None`,

      'python.lang.security.audit.dangerous-subprocess-use': `# Python Subprocess Injection Examples

import subprocess
import os

# Vulnerable: subprocess.call with shell=True
def vulnerable_subprocess1(user_input):
    subprocess.call(f"ls {user_input}", shell=True)
    # shell=True allows command injection

# Vulnerable: subprocess.run with shell=True
def vulnerable_subprocess2(filename):
    subprocess.run(f"cat {filename}", shell=True)
    # Can execute arbitrary commands

# Vulnerable: subprocess.Popen with shell=True
def vulnerable_subprocess3(directory):
    process = subprocess.Popen(f"rm -rf {directory}", shell=True)
    # Dangerous file operations

# Vulnerable: os.system
def vulnerable_os_system(command):
    os.system(command)
    # os.system always uses shell, very dangerous

# Safe: subprocess without shell
def safe_subprocess1(filename):
    subprocess.run(['cat', filename])
    # Array prevents injection

# Safe: Input validation
def safe_subprocess2(filename):
    if filename.isalnum() and not '..' in filename:
        subprocess.run(['cat', filename])`,

      // Generic Rules
      'generic.secrets.security.detected-private-key': `# Configuration file with private key embedded

# Application configuration with secrets
server:
  host: localhost
  port: 8080

# WARNING: Private key should not be in source code!
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4qiWZLHLmpxddngbPOUcjshUQYYm5eNOHgHJ8ks9DzgHrE5L
KpPRGCUWYgQ1HsOEjVdTgDZggTc8rSCAXGkFJO2GNEJxkM4HNmKnTY5wHqYKUgGT
9H5oZZGJ8FngQgJ9BgIqXnWAQbMGfYGHLKJ5GCJoRPPKJKp5H8nELYGJtDNu4HtG
fJ8ks9DzgHrE5LKpPRGCUWYgQ1HsOEjVdTgDZggTc8rSCAXGkFJO2GNEJxkM4HNm
-----END RSA PRIVATE KEY-----

# Another private key example
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wn7KI5tHOKVj7+8oQ2j6rO7j1WcYGjOUJ2V7V7V7V7V7V7V7V7V7V7V7V7V7V7V7
-----END PRIVATE KEY-----

database:
  host: localhost
  user: admin`,

      'generic.secrets.security.detected-password': `# Configuration file with hardcoded passwords

# Database configuration - INSECURE!
database:
  host: localhost
  port: 5432
  username: admin
  password: "mySecretPassword123"  # This will be detected

# API configuration
api:
  endpoint: https://api.example.com
  api_key: "abc123def456789"
  secret_key: "superSecretAPIKey789"

# Authentication settings
auth:
  admin_password: "adminPass2023"
  user_passwd: "defaultUserPassword"
  jwt_secret: "myJWTSecretKey123456"

# Application secrets
app:
  encryption_key: "encryptionKey123456789"
  session_secret: "sessionSecret987654321"

# SAFE configuration examples:
safe_config:
  # Using environment variables (recommended)
  database_password: \${DB_PASSWORD}
  api_secret: \${API_SECRET}
  # Using external config files
  secret_file: /etc/secrets/app.key`
    }
    
    // 返回对应的代码，如果没有找到则返回 SQL 注入示例
    return codeExamples[ruleId] || codeExamples['sql-injection-detection']
  }

  const runSemgrep = async () => {
    setIsRunning(true)
    // 彻底清空之前的状态
    setHighlightedLines([])
    setScanResults([])
    setShowResults(false)
    
    // 检测代码语言 (使用CodeHighlighter组件中的detectLanguage函数)
    const detectLang = (code: string): string => {
      // 优先级更高的检测
      if (code.includes('def ') && (code.includes('pass') || code.includes('import') || code.includes('#') || /^\s*#/.test(code))) return 'python'
      if (code.includes('<?php') || code.includes('$_') || code.includes('function ') && code.includes('$')) return 'php'
      if (code.includes('func ') && code.includes('package ') && (code.includes('http.Request') || code.includes('fmt.') || code.includes('import ('))) return 'go'
      if (code.includes('package ') && code.includes('import ') && (code.includes('public ') || code.includes('class ') || code.includes('void '))) return 'java'
      if (code.includes('fn ') && (code.includes('let ') || code.includes('mut ') || code.includes('&str'))) return 'rust'
      if (code.includes('object ') && code.includes('def ') && code.includes('scala')) return 'scala'
      if (code.includes('interface ') && code.includes('type ') || code.includes(': string') || code.includes(': number')) return 'typescript'
      if (code.includes('#include') || code.includes('int main') || code.includes('std::')) return 'cpp'
      if (code.includes('<html') || code.includes('<div') || code.includes('<body') || code.includes('<!DOCTYPE')) return 'html'
      if (code.includes('function ') || code.includes('const ') || code.includes('let ') || code.includes('=>')) return 'javascript'
      
      // 基于文件内容特征的检测
      const lines = code.split('\n').filter(line => line.trim())
      if (lines.length > 0) {
        const firstLine = lines[0]
        if (firstLine.startsWith('package main') || firstLine.startsWith('package ')) {
          // 进一步检查是否为Go（不是Java）
          if (code.includes('func ') || code.includes('import (')) return 'go'
          if (code.includes('public class') || code.includes('import java')) return 'java'
        }
        if (firstLine.startsWith('#') && lines.some(line => line.includes('def '))) return 'python'
        if (firstLine.includes('<?php')) return 'php'
        if (firstLine.includes('<!DOCTYPE') || firstLine.includes('<html')) return 'html'
      }
      
      return 'java' // 默认为Java
    }
    
    const detectedLanguage = detectLang(codeContent)
    
    try {
      const response = await fetch('http://127.0.0.1:5000/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          rule: ruleContent,
          code: codeContent,
          language: detectedLanguage
        })
      })
      
      const result = await response.json()
      
      if (result.success && result.matches) {
        // 保存扫描结果
        setScanResults(result.matches)
        setShowResults(true)
        
        // 提取所有匹配的行号用于高亮
        const highlightLines: number[] = []
        result.matches.forEach((match: SemgrepMatch) => {
          const startLine = match.line_start
          const endLine = match.line_end
          
          // 如果开始行和结束行相同，只高亮这一行
          if (startLine === endLine) {
            if (!highlightLines.includes(startLine)) {
              highlightLines.push(startLine)
            }
          } else {
            // 如果跨多行，只高亮开始行和结束行，不高亮中间的行
            if (!highlightLines.includes(startLine)) {
              highlightLines.push(startLine)
            }
            if (!highlightLines.includes(endLine)) {
              highlightLines.push(endLine)
            }
          }
        })
        setHighlightedLines(highlightLines)
      } else {
        alert(`扫描失败: ${result.error || '未知错误'}`)
        setScanResults([])
        setShowResults(false)
      }
    } catch (error) {
      alert('无法连接到后端服务，请确保后端 API 正在运行 (http://127.0.0.1:5000)')
    } finally {
      setIsRunning(false)
    }
  }

  const toggleCategory = (index: number) => {
    setCategories((prev) => prev.map((cat, i) => (i === index ? { ...cat, expanded: !cat.expanded } : cat)))
  }

  const filteredCategories = categories.filter((cat) => cat.name.toLowerCase().includes(searchQuery.toLowerCase()))

  // 获取严重级别对应的颜色
  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'ERROR':
      case 'CRITICAL':
        return 'text-red-600 bg-red-50 border-red-200'
      case 'WARNING':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'INFO':
        return 'text-blue-600 bg-blue-50 border-blue-200'
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  return (
    <div className="h-screen flex bg-gray-50">
      {/* 删除确认对话框 */}
      {deleteConfirm.show && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                <Trash2 className="w-5 h-5 text-red-600" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">确认删除</h3>
                <p className="text-sm text-gray-500">此操作无法撤销</p>
              </div>
            </div>
            <p className="text-gray-700 mb-6">
              确定要删除规则 "<span className="font-medium">{deleteConfirm.ruleName}</span>" 吗？
              这将同时删除规则文件和对应的测试代码。
            </p>
            <div className="flex justify-end gap-3">
              <Button
                onClick={cancelDelete}
                variant="outline"
                disabled={isDeleting}
              >
                取消
              </Button>
              <Button
                onClick={confirmDeleteRule}
                className="bg-red-600 hover:bg-red-700 text-white"
                disabled={isDeleting}
              >
                {isDeleting ? (
                  <>
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                    删除中...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4 mr-2" />
                    删除
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar - Rule Library */}
      <div className="w-80 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-4 border-b border-gray-100">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-5 h-5 bg-gray-800 rounded flex items-center justify-center">
              <div className="w-3 h-3 bg-white rounded-sm"></div>
            </div>
            <span className="font-medium text-gray-900">Library</span>
          </div>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="e.g.: python.flask"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-gray-50 text-gray-900 pl-10 pr-4 py-2.5 rounded-md border border-gray-200 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <Button 
            onClick={startCreateNewRule}
            className="w-full mt-3 bg-green-600 hover:bg-green-700 text-white"
            size="sm"
          >
            <Plus className="w-4 h-4 mr-2" />
            新建规则
          </Button>
        </div>

        <div className="flex-1 overflow-auto">
          {isLoadingRules ? (
            <div className="flex items-center justify-center p-8">
              <Loader className="w-6 h-6 animate-spin text-blue-500" />
              <span className="ml-2 text-sm text-gray-500">加载规则库...</span>
            </div>
          ) : (
            filteredCategories.map((category, index) => (
              <div key={category.name} className="border-b border-gray-50 last:border-b-0">
                <button
                  onClick={() => toggleCategory(index)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-50 text-left transition-colors group"
                >
                  <div className="flex items-center gap-2.5">
                    {category.expanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-gray-400" />
                    )}
                    {category.expanded ? (
                      <FolderOpen className="w-4 h-4 text-gray-500" />
                    ) : (
                      <Folder className="w-4 h-4 text-gray-500" />
                    )}
                    <span className="text-sm text-gray-700 font-medium">{category.name}</span>
                  </div>
                  <span className="text-xs text-gray-500 font-medium">{category.count}</span>
                </button>

                {category.expanded && category.rules && (
                  <div className="bg-white">
                    {category.rules.map((rule) => (
                      <div
                        key={rule.id}
                        className="flex items-center justify-between px-8 py-1.5 hover:bg-gray-50 group"
                      >
                        <button
                          onClick={() => loadRuleContent(rule.id)}
                          className="flex items-center gap-2.5 flex-1 text-left"
                        >
                          <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                          <span className="text-sm text-gray-600 truncate">{rule.name}</span>
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            showDeleteConfirm(rule.id, rule.name)
                          }}
                          className="opacity-0 group-hover:opacity-100 p-1 hover:bg-red-100 rounded transition-opacity"
                          title="删除规则"
                        >
                          <Trash2 className="w-3 h-3 text-red-500" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Rule Editor */}
      <div className="flex-1 flex flex-col bg-white border-r border-gray-200">
        <div className="h-16 px-4 border-b border-gray-200 flex items-center justify-between">
          {isCreatingRule ? (
            <>
              <div className="flex items-center gap-4">
                <input
                  type="text"
                  placeholder="规则名称 (如: sqli)"
                  value={newRuleData.name}
                  onChange={(e) => setNewRuleData(prev => ({ ...prev, name: e.target.value }))}
                  className="border border-gray-300 rounded px-2 py-1 text-sm w-32"
                />
                <input
                  type="text"
                  placeholder="分类 (如: Java Security)"
                  value={newRuleData.category}
                  onChange={(e) => setNewRuleData(prev => ({ ...prev, category: e.target.value }))}
                  className="border border-gray-300 rounded px-2 py-1 text-sm w-36"
                />
                <select
                  value={newRuleData.language}
                  onChange={(e) => {
                    const newLang = e.target.value
                    setNewRuleData(prev => ({ ...prev, language: newLang }))
                    // 更新代码模板
                    setCodeContent(createNewCodeTemplate(newLang))
                    // 更新规则模板（如果有名称和分类的话）
                    if (newRuleData.name && newRuleData.category) {
                      setRuleContent(createNewRuleTemplate(newRuleData.name, newRuleData.category, newLang))
                    }
                  }}
                  className="border border-gray-300 rounded px-2 py-1 text-sm"
                >
                  <option value="java">Java</option>
                  <option value="python">Python</option>
                  <option value="javascript">JavaScript</option>
                  <option value="typescript">TypeScript</option>
                  <option value="go">Go</option>
                  <option value="php">PHP</option>
                  <option value="rust">Rust</option>
                  <option value="scala">Scala</option>
                  <option value="html">HTML</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  onClick={saveNewRule}
                  className="bg-green-600 hover:bg-green-700 text-white"
                  size="sm"
                >
                  <Save className="w-4 h-4 mr-1" />
                  保存
                </Button>
                <Button
                  onClick={cancelCreateNewRule}
                  variant="outline"
                  size="sm"
                >
                  <X className="w-4 h-4 mr-1" />
                  取消
                </Button>
              </div>
            </>
          ) : (
            <h2 className="text-lg font-medium text-gray-900">{getRuleId()}</h2>
          )}
        </div>
        <div className="flex-1 p-4 bg-gray-50">
          <div className="h-full bg-white rounded border border-gray-200 overflow-hidden">
            <YamlHighlighter content={ruleContent} onChange={setRuleContent} />
          </div>
        </div>
      </div>

      {/* Code Editor */}
      <div className="flex-1 flex flex-col bg-white">
        <div className="h-16 px-4 border-b border-gray-200 flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-900">
            {isCreatingRule ? `${newRuleData.language || 'java'} 测试代码` : getCodeFileName()}
          </h2>
          {!isCreatingRule && (
            <Button onClick={runSemgrep} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700" size="sm">
              <Play className="w-4 h-4 mr-1" />
              {isRunning ? "Running..." : "Run"}
            </Button>
          )}
        </div>
        <div className="flex-1 flex flex-col p-4 overflow-hidden bg-gray-50">
          <div className="flex-1 bg-white rounded border border-gray-200 overflow-hidden mb-4">
            <CodeHighlighter content={codeContent} highlightedLines={highlightedLines} onChange={setCodeContent} />
          </div>
          
          {/* 扫描结果面板 */}
          {showResults && (
            <div className="h-64 bg-white rounded border border-gray-200 flex flex-col">
              <div className="px-4 py-2 border-b border-gray-200 bg-gray-50 rounded-t">
                <h3 className="text-sm font-medium text-gray-900">
                  扫描结果 ({scanResults.length} 个问题)
                </h3>
              </div>
              <div className="flex-1 overflow-auto p-4">
                {scanResults.length === 0 ? (
                  <div className="text-center text-gray-500 py-8">
                    <div className="text-green-600 text-lg mb-2">✅</div>
                    <p>恭喜！未发现安全问题</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {scanResults.map((match, index) => (
                      <div key={index} className="border border-gray-200 rounded p-3 hover:bg-gray-50">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(match.severity)}`}>
                              {match.severity}
                            </span>
                            <span className="text-sm text-gray-600">行 {match.line_start}-{match.line_end}</span>
                          </div>
                          <span className="text-xs text-gray-400">{match.rule_id}</span>
                        </div>
                        <p className="text-sm text-gray-800 mb-2">{match.message}</p>
                        {match.code && (
                          <div className="bg-gray-100 rounded p-2 text-xs font-mono text-gray-700 overflow-x-auto">
                            {match.code}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
