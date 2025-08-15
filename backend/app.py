#!/usr/bin/env python3
"""
Semgrep Playground 后端 API
提供 semgrep 扫描功能的 REST API
"""

import os
import tempfile
import subprocess
import json
import yaml
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 允许前端跨域请求

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({"status": "ok", "message": "Semgrep Playground API is running"})

@app.route('/scan', methods=['POST'])
def scan_code():
    """
    扫描代码接口
    请求体格式：
    {
        "rule": "yaml格式的semgrep规则",
        "code": "要扫描的代码",
        "language": "代码语言（可选，默认从规则推断）"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "请求体不能为空"}), 400
        
        rule_content = data.get('rule')
        code_content = data.get('code')
        language = data.get('language', 'java')  # 默认 java
        
        if not rule_content or not code_content:
            return jsonify({"error": "rule 和 code 字段不能为空"}), 400
        
        # 创建临时文件
        with tempfile.TemporaryDirectory() as temp_dir:
            # 写入规则文件
            rule_file = os.path.join(temp_dir, 'rule.yaml')
            with open(rule_file, 'w', encoding='utf-8') as f:
                f.write(rule_content)
            
            # 写入代码文件
            code_file = os.path.join(temp_dir, f'test.{get_file_extension(language)}')
            with open(code_file, 'w', encoding='utf-8') as f:
                f.write(code_content)
            
            # 执行 semgrep 扫描
            result = run_semgrep(rule_file, code_file, language)
            
            return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": f"扫描失败: {str(e)}"}), 500

def get_file_extension(language):
    """根据语言获取文件扩展名"""
    extensions = {
        'java': 'java',
        'python': 'py',
        'javascript': 'js',
        'typescript': 'ts',
        'go': 'go',
        'c': 'c',
        'cpp': 'cpp',
        'php': 'php',
        'ruby': 'rb',
        'rust': 'rs',
    }
    return extensions.get(language.lower(), 'txt')

def run_semgrep(rule_file, code_file, language='unknown'):
    """执行 semgrep 扫描"""
    try:
        # 构建 semgrep 命令
        cmd = [
            'semgrep',
            '--config', rule_file,
            '--json',
            '--no-git-ignore',
            '--disable-version-check',
            '--pro',  # 启用Pro功能支持污点分析等高级规则
            code_file
        ]
        
        
        # 执行命令
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # 30秒超时
        )
        
        # 解析结果
        if result.returncode == 0:
            # 成功执行
            if result.stdout.strip():
                try:
                    semgrep_output = json.loads(result.stdout)
                    return parse_semgrep_results(semgrep_output)
                except json.JSONDecodeError:
                    return {
                        "success": True,
                        "matches": [],
                        "message": "扫描完成，未发现匹配项"
                    }
            else:
                return {
                    "success": True,
                    "matches": [],
                    "message": "扫描完成，未发现匹配项"
                }
        else:
            # 执行失败
            error_msg = result.stderr or result.stdout or "未知错误"
            return {
                "success": False,
                "error": f"Semgrep 执行失败: {error_msg}",
                "matches": []
            }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "扫描超时（30秒）",
            "matches": []
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "未找到 semgrep 命令，请确保已安装 semgrep",
            "matches": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"执行错误: {str(e)}",
            "matches": []
        }

def find_test_code(rule_id, test_code_dir):
    """查找规则对应的测试代码"""
    try:
        # 解析语言和规则名
        parts = rule_id.split('.')
        if len(parts) >= 2:
            language = parts[0]  # 例如：'go', 'python', 'java'
            rule_name = parts[-1]  # 例如：'tainted-sql-string'
        else:
            language = 'unknown'
            rule_name = rule_id
        
        # 尝试不同的命名模式
        patterns = [
            f"{rule_id.replace('.', '-')}.java",
            f"{rule_id.replace('.', '-')}.py",
            f"{rule_id.replace('.', '-')}.js",
            f"{rule_id.replace('.', '-')}.go",
            f"{rule_id.replace('.', '-')}.php",
            f"{rule_id.replace('.', '-')}.rs",
            f"{language}-{rule_name}.java",  # 例如：'go-tainted-sql-string.go'
            f"{language}-{rule_name}.py",
            f"{language}-{rule_name}.js", 
            f"{language}-{rule_name}.go",
            f"{language}-{rule_name}.php",
            f"{language}-{rule_name}.rs",
            f"{rule_name}.java",  # 只用最后一部分
            f"{rule_name}.py",
            f"{rule_name}.js",
            f"{rule_name}.go",
            f"{rule_name}.php",
            f"{rule_name}.rs",
        ]
        
        # 查找匹配的文件
        if os.path.exists(test_code_dir):
            for file_name in os.listdir(test_code_dir):
                for pattern in patterns:
                    if file_name == pattern:
                        file_path = os.path.join(test_code_dir, file_name)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            return f.read()
        
        return None
    except Exception:
        return None

def parse_semgrep_results(semgrep_output):
    """解析 semgrep 输出结果"""
    try:
        results = semgrep_output.get('results', [])
        matches = []
        
        for result in results:
            match = {
                "rule_id": result.get('check_id', ''),
                "message": result.get('extra', {}).get('message', ''),
                "severity": result.get('extra', {}).get('severity', 'INFO'),
                "line_start": result.get('start', {}).get('line', 0),
                "line_end": result.get('end', {}).get('line', 0),
                "col_start": result.get('start', {}).get('col', 0),
                "col_end": result.get('end', {}).get('col', 0),
                "path": result.get('path', ''),
                "code": result.get('extra', {}).get('lines', '')
            }
            matches.append(match)
        
        return {
            "success": True,
            "matches": matches,
            "message": f"扫描完成，发现 {len(matches)} 个匹配项"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"解析结果失败: {str(e)}",
            "matches": []
        }

@app.route('/validate-rule', methods=['POST'])
def validate_rule():
    """验证规则语法"""
    try:
        data = request.get_json()
        rule_content = data.get('rule')
        
        if not rule_content:
            return jsonify({"valid": False, "error": "规则内容不能为空"}), 400
        
        # 尝试解析 YAML
        try:
            yaml.safe_load(rule_content)
            return jsonify({"valid": True, "message": "规则语法正确"})
        except yaml.YAMLError as e:
            return jsonify({"valid": False, "error": f"YAML 语法错误: {str(e)}"})
    
    except Exception as e:
        return jsonify({"valid": False, "error": f"验证失败: {str(e)}"}), 500

@app.route('/rules', methods=['GET'])
def get_semgrep_rules():
    """获取 Semgrep 规则库"""
    try:
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        categories = {}
        
        # 扫描规则文件夹
        if os.path.exists(rules_dir):
            for category_folder in os.listdir(rules_dir):
                category_path = os.path.join(rules_dir, category_folder)
                if os.path.isdir(category_path):
                    category_name = category_folder.replace('-', ' ').title()
                    rules = []
                    
                    # 扫描该分类下的规则文件
                    for rule_file in os.listdir(category_path):
                        if rule_file.endswith('.yaml') or rule_file.endswith('.yml'):
                            rule_name = rule_file.replace('.yaml', '').replace('.yml', '')
                            rule_id = f"{category_folder}.{rule_name}"
                            rules.append({
                                "id": rule_id,
                                "name": rule_name,
                                "category": category_name,
                                "file_path": os.path.join(category_path, rule_file)
                            })
                    
                    if rules:
                        categories[category_name] = rules
        
        # 如果没有找到文件系统规则，使用预定义规则作为后备
        if not categories:
            categories = {
                "Java Security": [
                    {"id": "java.lang.security.audit.sqli", "name": "sqli", "category": "Java Security"},
                    {"id": "java.lang.security.audit.xss", "name": "xss", "category": "Java Security"},
                    {"id": "java.lang.security.audit.crypto", "name": "crypto", "category": "Java Security"},
                    {"id": "java.lang.security.audit.hardcoded-secret", "name": "hardcoded-secret", "category": "Java Security"},
                ],
                "JavaScript Security": [
                    {"id": "javascript.lang.security.audit.sqli", "name": "sqli", "category": "JavaScript Security"},
                    {"id": "javascript.lang.security.audit.xss", "name": "xss", "category": "JavaScript Security"},
                    {"id": "javascript.lang.security.audit.dangerous-object-assign", "name": "dangerous-object-assign", "category": "JavaScript Security"},
                ],
                "Python Security": [
                    {"id": "python.lang.security.audit.sqli", "name": "sqli", "category": "Python Security"},
                    {"id": "python.lang.security.audit.code-injection", "name": "code-injection", "category": "Python Security"},
                    {"id": "python.lang.security.audit.dangerous-subprocess-use", "name": "dangerous-subprocess-use", "category": "Python Security"},
                ],
                "Example Rules": [
                    {"id": "sql-injection-detection", "name": "sql-injection-detection", "category": "Example Rules"},
                ],
                "Generic Rules": [
                    {"id": "generic.secrets.security.detected-private-key", "name": "detected-private-key", "category": "Generic Rules"},
                    {"id": "generic.secrets.security.detected-password", "name": "detected-password", "category": "Generic Rules"},
                ]
            }
        
        return jsonify({
            "success": True,
            "categories": categories
        })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"获取规则失败: {str(e)}"
        })

@app.route('/rule/<path:rule_id>', methods=['GET'])
def get_rule_content(rule_id):
    """获取特定规则的内容"""
    try:
        # 首先尝试从文件系统读取
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        test_code_dir = os.path.join(os.path.dirname(__file__), 'test-code')
        
        # 解析规则ID以找到对应的文件
        parts = rule_id.split('.')
        if len(parts) >= 2:
            category_folder = parts[0]  # 例如：'go'
            rule_name = parts[-1]  # 取最后一部分作为规则名，例如：'tainted-sql-string'
            
            # 构建规则文件路径
            rule_file_path = os.path.join(rules_dir, category_folder, f"{rule_name}.yaml")
            
            if os.path.exists(rule_file_path):
                with open(rule_file_path, 'r', encoding='utf-8') as f:
                    rule_content = f.read()
                
                # 查找对应的测试代码
                test_code = find_test_code(rule_id, test_code_dir)
                
                return jsonify({
                    "success": True,
                    "content": rule_content,
                    "test_code": test_code
                })
        
        # 如果文件系统中没有找到，使用预定义的规则内容
        rule_contents = {
            # Example Rules
            "sql-injection-detection": """rules:
  - id: sql-injection-detection
    languages:
      - java
    severity: ERROR
    message: "SQL injection vulnerability: user input is concatenated directly to SQL query"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
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
              $STMT.executeQuery("..." + $VAR + "...");""",

            # Java Security Rules
            "java.lang.security.audit.sqli": """rules:
  - id: java.lang.security.audit.sqli
    languages:
      - java
    severity: ERROR
    message: "SQL injection vulnerability detected"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
    patterns:
      - pattern-either:
          - pattern: |
              String $SQL = "..." + $VAR + "...";
              ...
              $STMT.executeQuery($SQL);
          - pattern: |
              String $SQL = "..." + $VAR + "...";
              ...
              $STMT.execute($SQL);
          - pattern: |
              $STMT.executeQuery("..." + $VAR + "...");
          - pattern: |
              $STMT.execute("..." + $VAR + "...");""",

            "java.lang.security.audit.xss": """rules:
  - id: java.lang.security.audit.xss
    languages:
      - java
    severity: ERROR
    message: "XSS vulnerability: user input is written to output without escaping"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-79: Cross-site Scripting"
      owasp: "A03:2021 - Injection"
    patterns:
      - pattern-either:
          - pattern: |
              $OUT.println("..." + $VAR + "...");
          - pattern: |
              $OUT.print("..." + $VAR + "...");
          - pattern: |
              $OUT.write("..." + $VAR + "...");
          - pattern: |
              $RESP.getWriter().println("..." + $VAR + "...");""",

            "java.lang.security.audit.crypto": """rules:
  - id: java.lang.security.audit.crypto
    languages:
      - java
    severity: WARNING
    message: "Weak cryptographic algorithm detected"
    metadata:
      category: security
      confidence: HIGH
      impact: MEDIUM
      cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
    patterns:
      - pattern-either:
          - pattern: |
              KeyGenerator.getInstance("DES");
          - pattern: |
              Cipher.getInstance("DES");
          - pattern: |
              MessageDigest.getInstance("MD5");
          - pattern: |
              MessageDigest.getInstance("SHA1");
          - pattern: |
              MessageDigest.getInstance("SHA-1");""",

            "java.lang.security.audit.hardcoded-secret": """rules:
  - id: java.lang.security.audit.hardcoded-secret
    languages:
      - java
    severity: ERROR
    message: "Hardcoded secret detected"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-798: Use of Hard-coded Credentials"
    patterns:
      - pattern-either:
          - pattern: |
              String $VAR = "...$SECRET...";
          - pattern: |
              String password = "...";
          - pattern: |
              String apiKey = "...";
          - pattern: |
              String secret = "...";
      - metavariable-regex:
          metavariable: $SECRET
          regex: (?i)(password|secret|key|token|api).*[a-zA-Z0-9]{8,}""",

            # JavaScript Security Rules
            "javascript.lang.security.audit.sqli": """rules:
  - id: javascript.lang.security.audit.sqli
    languages:
      - javascript
      - typescript
    severity: ERROR
    message: "SQL injection vulnerability detected"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
    patterns:
      - pattern-either:
          - pattern: |
              $DB.query("..." + $VAR + "...");
          - pattern: |
              $DB.execute("..." + $VAR + "...");
          - pattern: |
              $CONN.query("..." + $VAR + "...");
          - pattern: |
              $CONN.execute("..." + $VAR + "...");""",

            "javascript.lang.security.audit.xss": """rules:
  - id: javascript.lang.security.audit.xss
    languages:
      - javascript
      - typescript
    severity: ERROR
    message: "XSS vulnerability: user input is written to DOM without escaping"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-79: Cross-site Scripting"
      owasp: "A03:2021 - Injection"
    patterns:
      - pattern-either:
          - pattern: |
              $EL.innerHTML = $VAR;
          - pattern: |
              document.write($VAR);
          - pattern: |
              $EL.outerHTML = $VAR;
          - pattern: |
              $($EL).html($VAR);""",

            "javascript.lang.security.audit.dangerous-object-assign": """rules:
  - id: javascript.lang.security.audit.dangerous-object-assign
    languages:
      - javascript
      - typescript
    severity: WARNING
    message: "Dangerous Object.assign usage that could lead to prototype pollution"
    metadata:
      category: security
      confidence: MEDIUM
      impact: HIGH
      cwe: "CWE-1321: Prototype Pollution"
    patterns:
      - pattern-either:
          - pattern: |
              Object.assign($TARGET, $SOURCE);
          - pattern: |
              _.merge($TARGET, $SOURCE);
          - pattern: |
              $.extend($TARGET, $SOURCE);""",

            # Python Security Rules
            "python.lang.security.audit.sqli": """rules:
  - id: python.lang.security.audit.sqli
    languages:
      - python
    severity: ERROR
    message: "SQL injection vulnerability detected"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
    patterns:
      - pattern-either:
          - pattern: |
              $CURSOR.execute("..." + $VAR + "...")
          - pattern: |
              $CURSOR.execute(f"...{$VAR}...")
          - pattern: |
              $CURSOR.execute("..." % $VAR)
          - pattern: |
              $CURSOR.execute("...".format($VAR))""",

            "python.lang.security.audit.code-injection": """rules:
  - id: python.lang.security.audit.code-injection
    languages:
      - python
    severity: ERROR
    message: "Code injection vulnerability detected"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-94: Code Injection"
    patterns:
      - pattern-either:
          - pattern: |
              eval($VAR)
          - pattern: |
              exec($VAR)
          - pattern: |
              compile($VAR, ...)""",

            "python.lang.security.audit.dangerous-subprocess-use": """rules:
  - id: python.lang.security.audit.dangerous-subprocess-use
    languages:
      - python
    severity: ERROR
    message: "Dangerous subprocess usage that could lead to command injection"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-78: Command Injection"
    patterns:
      - pattern-either:
          - pattern: |
              subprocess.call($CMD, shell=True)
          - pattern: |
              subprocess.run($CMD, shell=True)
          - pattern: |
              subprocess.Popen($CMD, shell=True)
          - pattern: |
              os.system($CMD)""",

            # Generic Rules
            "generic.secrets.security.detected-private-key": """rules:
  - id: generic.secrets.security.detected-private-key
    languages:
      - generic
    severity: ERROR
    message: "Private key detected in source code"
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
      cwe: "CWE-312: Cleartext Storage of Sensitive Information"
    patterns:
      - pattern-regex: |
          -----BEGIN [A-Z ]*PRIVATE KEY-----""",

            "generic.secrets.security.detected-password": """rules:
  - id: generic.secrets.security.detected-password
    languages:
      - generic
    severity: WARNING
    message: "Potential password detected in source code"
    metadata:
      category: security
      confidence: MEDIUM
      impact: HIGH
      cwe: "CWE-798: Use of Hard-coded Credentials"
    patterns:
      - pattern-regex: |
          (?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']"""
        }
        
        # 检查是否有预定义的规则内容
        if rule_id in rule_contents:
            return jsonify({
                "success": True,
                "content": rule_contents[rule_id]
            })
        else:
            # 返回一个基本模板
            template = f"""rules:
  - id: {rule_id}
    languages:
      - generic
    severity: WARNING
    message: "Custom rule template for {rule_id}"
    patterns:
      - pattern: $PLACEHOLDER
    # Please customize this rule according to your needs
    # Visit https://semgrep.dev/docs/ for more information"""
            
            return jsonify({
                "success": True,
                "content": template
            })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"获取规则内容失败: {str(e)}"
        })

@app.route('/rule/<path:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """删除规则"""
    try:
        # 解析规则ID
        parts = rule_id.split('.')
        if len(parts) >= 2:
            category_folder = parts[0]  # 例如：'go'
            rule_name = parts[-1]      # 例如：'tainted-sql-string'
        else:
            return jsonify({"success": False, "error": "无效的规则ID格式"}), 400
        
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        test_code_dir = os.path.join(os.path.dirname(__file__), 'test-code')
        
        # 构建规则文件路径
        rule_file_path = os.path.join(rules_dir, category_folder, f"{rule_name}.yaml")
        
        # 检查规则文件是否存在
        if not os.path.exists(rule_file_path):
            return jsonify({"success": False, "error": "规则文件不存在"}), 404
        
        # 删除规则文件
        os.remove(rule_file_path)
        
        # 查找并删除对应的测试代码文件
        deleted_test_files = []
        if os.path.exists(test_code_dir):
            # 尝试不同的测试代码命名模式
            test_file_patterns = [
                f"{rule_id.replace('.', '-')}.java",
                f"{rule_id.replace('.', '-')}.py", 
                f"{rule_id.replace('.', '-')}.js",
                f"{rule_id.replace('.', '-')}.go",
                f"{rule_id.replace('.', '-')}.php",
                f"{rule_id.replace('.', '-')}.rs",
                f"{category_folder}-{rule_name}.java",
                f"{category_folder}-{rule_name}.py",
                f"{category_folder}-{rule_name}.js", 
                f"{category_folder}-{rule_name}.go",
                f"{category_folder}-{rule_name}.php",
                f"{category_folder}-{rule_name}.rs",
            ]
            
            for pattern in test_file_patterns:
                test_file_path = os.path.join(test_code_dir, pattern)
                if os.path.exists(test_file_path):
                    os.remove(test_file_path)
                    deleted_test_files.append(pattern)
        
        # 检查分类文件夹是否为空，如果是则删除
        category_path = os.path.join(rules_dir, category_folder)
        if os.path.exists(category_path) and not os.listdir(category_path):
            os.rmdir(category_path)
        
        return jsonify({
            "success": True,
            "message": "规则删除成功",
            "deleted_rule": rule_file_path,
            "deleted_test_files": deleted_test_files
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"删除规则失败: {str(e)}"
        }), 500

@app.route('/create-rule', methods=['POST'])
def create_rule():
    """创建新的规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "请求体不能为空"}), 400
        
        name = data.get('name')
        category = data.get('category')
        language = data.get('language', 'java')
        rule_content = data.get('rule_content')
        test_code = data.get('test_code')
        
        if not all([name, category, rule_content, test_code]):
            return jsonify({"success": False, "error": "缺少必需的字段"}), 400
        
        # 创建规则文件夹
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        category_folder = category.lower().replace(' ', '-')
        category_path = os.path.join(rules_dir, category_folder)
        
        os.makedirs(category_path, exist_ok=True)
        
        # 创建测试代码文件夹
        test_code_dir = os.path.join(os.path.dirname(__file__), 'test-code')
        os.makedirs(test_code_dir, exist_ok=True)
        
        # 保存规则文件
        rule_file_path = os.path.join(category_path, f"{name}.yaml")
        if os.path.exists(rule_file_path):
            return jsonify({"success": False, "error": "规则文件已存在"}), 400
        
        with open(rule_file_path, 'w', encoding='utf-8') as f:
            f.write(rule_content)
        
        # 保存测试代码文件
        file_extensions = {
            'java': 'java',
            'python': 'py',
            'javascript': 'js',
            'typescript': 'ts',
            'go': 'go',
            'php': 'php',
            'rust': 'rs',
            'scala': 'scala',
            'html': 'html'
        }
        ext = file_extensions.get(language, 'java')
        code_file_path = os.path.join(test_code_dir, f"{category_folder}-{name}.{ext}")
        
        with open(code_file_path, 'w', encoding='utf-8') as f:
            f.write(test_code)
        
        return jsonify({
            "success": True,
            "message": "规则创建成功",
            "rule_file": rule_file_path,
            "code_file": code_file_path
        })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"创建规则失败: {str(e)}"
        }), 500

if __name__ == '__main__':
    print("启动 Semgrep Playground API...")
    print("健康检查: http://127.0.0.1:5000/health")
    print("扫描接口: POST http://127.0.0.1:5000/scan")
    print("规则验证: POST http://127.0.0.1:5000/validate-rule")
    app.run(host='127.0.0.1', port=5000, debug=True)