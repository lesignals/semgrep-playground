"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Play, ChevronRight, ChevronDown, Search, Folder, FolderOpen } from "lucide-react"

const defaultRule = `rules:
  - id: tainted-sql-from-http-request
    languages:
      - java
    severity: ERROR
    message: This rule is deprecated
    pattern-sources:
      - pattern: "*"
    pattern-sinks:
      - pattern: "*"
    mode: taint`

const defaultCode = `/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark
 * Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the
 * terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00001")
public class bad1 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String param = request.getParameter("BenchmarkTest00001");
        if (param == null) param = "";
        
        String sql = "SELECT * FROM users WHERE name = '" + param + "'";
        // This is vulnerable to SQL injection
    }`

const ruleCategories = [
  { name: "lesliesc", count: 2, expanded: false },
  { name: "Semgrep Registry", count: 2022, expanded: true },
  { name: "ai", count: 25, expanded: false },
  { name: "apex", count: 18, expanded: false },
  { name: "bash", count: 7, expanded: false },
  { name: "c", count: 16, expanded: false },
  { name: "clojure", count: 5, expanded: false },
  { name: "csharp", count: 52, expanded: false },
  { name: "dockerfile", count: 37, expanded: false },
  { name: "elixir", count: 7, expanded: false },
  { name: "generic", count: 257, expanded: false },
  { name: "go", count: 81, expanded: false },
  { name: "html", count: 6, expanded: false },
  { name: "java", count: 130, expanded: false },
  { name: "javascript", count: 182, expanded: false },
  { name: "json", count: 4, expanded: false },
  { name: "kotlin", count: 14, expanded: false },
  { name: "ocaml", count: 33, expanded: false },
  { name: "php", count: 64, expanded: false },
  { name: "problem-based-packs", count: 37, expanded: false },
  { name: "python", count: 378, expanded: false },
  { name: "ruby", count: 94, expanded: false },
  { name: "rust", count: 10, expanded: false },
  { name: "scala", count: 27, expanded: false },
  { name: "solidity", count: 50, expanded: false },
  { name: "swift", count: 4, expanded: false },
  { name: "template", count: 1, expanded: false },
  { name: "terraform", count: 364, expanded: false },
]

const YamlHighlighter = ({ content, onChange }: { content: string; onChange: (value: string) => void }) => {
  const highlightYaml = (text: string) => {
    return text
      .replace(
        /(^|\n)(\s*)([\w-]+)(\s*)(:)/gm,
        '$1$2<span class="text-blue-600 font-medium">$3</span>$4<span class="text-gray-600">$5</span>',
      )
      .replace(/(\s+)(-\s+)/gm, '$1<span class="text-purple-600">$2</span>')
      .replace(/(:\s*)([^\n]+)/gm, '$1<span class="text-green-600">$2</span>')
      .replace(/(\s+)(ERROR|WARNING|INFO)/gm, '$1<span class="text-red-600 font-semibold">$2</span>')
      .replace(/(#[^\n]*)/gm, '<span class="text-gray-400 italic">$1</span>')
  }

  return (
    <div className="relative h-full">
      <textarea
        value={content}
        onChange={(e) => onChange(e.target.value)}
        className="absolute inset-0 w-full h-full font-mono text-sm resize-none border-0 focus:ring-0 bg-transparent text-transparent caret-black z-10 outline-none"
        spellCheck={false}
      />
      <div
        className="absolute inset-0 w-full h-full font-mono text-sm p-3 overflow-auto pointer-events-none whitespace-pre-wrap break-words"
        dangerouslySetInnerHTML={{ __html: highlightYaml(content) }}
      />
    </div>
  )
}

const JavaHighlighter = ({ content, highlightedLines }: { content: string; highlightedLines: number[] }) => {
  const highlightJava = (text: string, lineNumber: number) => {
    return (
      text
        // Keywords
        .replace(
          /\b(public|private|protected|static|final|class|interface|extends|implements|import|package|void|int|String|boolean|if|else|for|while|try|catch|throw|throws|return|new|this|super)\b/g,
          '<span style="color: #7c3aed; font-weight: 500;">$1</span>',
        )
        // Annotations
        .replace(/(@\w+)/g, '<span style="color: #ca8a04;">$1</span>')
        // Strings
        .replace(/"([^"\\]|\\.)*"/g, '<span style="color: #16a34a;">"$1"</span>')
        // Comments
        .replace(/(\/\*[\s\S]*?\*\/)/g, '<span style="color: #9ca3af; font-style: italic;">$1</span>')
        .replace(/(\/\/.*$)/gm, '<span style="color: #9ca3af; font-style: italic;">$1</span>')
        // Numbers
        .replace(/\b(\d+)\b/g, '<span style="color: #2563eb;">$1</span>')
        // Method calls
        .replace(/(\w+)(\s*)(\()/g, '<span style="color: #1d4ed8;">$1</span>$2$3')
    )
  }

  const lines = content.split("\n")
  return (
    <div className="font-mono text-sm">
      {lines.map((line, index) => {
        const lineNumber = index + 1
        const isHighlighted = highlightedLines.includes(lineNumber)
        return (
          <div key={index} className={`flex ${isHighlighted ? "bg-red-50 border-l-2 border-red-400" : ""}`}>
            <div className="w-8 text-right text-gray-400 text-sm mr-4 select-none flex-shrink-0 py-0.5">
              {lineNumber}
            </div>
            <div className="flex-1 py-0.5">
              <code
                className="text-sm"
                dangerouslySetInnerHTML={{
                  __html: highlightJava(line, lineNumber),
                }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function SimpleSemgrepInterface() {
  const [ruleContent, setRuleContent] = useState(defaultRule)
  const [codeContent, setCodeContent] = useState(defaultCode)
  const [highlightedLines, setHighlightedLines] = useState<number[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [categories, setCategories] = useState(ruleCategories)
  const [searchQuery, setSearchQuery] = useState("")

  const runSemgrep = async () => {
    setIsRunning(true)
    setTimeout(() => {
      // Simulate finding matches on lines that contain SQL injection vulnerability
      const matches = [35, 36] // Lines with SQL injection
      setHighlightedLines(matches)
      setIsRunning(false)
    }, 1500)
  }

  const toggleCategory = (index: number) => {
    setCategories((prev) => prev.map((cat, i) => (i === index ? { ...cat, expanded: !cat.expanded } : cat)))
  }

  const filteredCategories = categories.filter((cat) => cat.name.toLowerCase().includes(searchQuery.toLowerCase()))

  return (
    <div className="h-screen flex bg-gray-50">
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
        </div>

        <div className="flex-1 overflow-auto">
          {filteredCategories.map((category, index) => (
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

              {category.expanded && category.name === "Semgrep Registry" && (
                <div className="bg-white">
                  {ruleCategories.slice(2).map((subCategory) => (
                    <div
                      key={subCategory.name}
                      className="flex items-center justify-between px-4 py-1.5 hover:bg-gray-50 group"
                    >
                      <div className="flex items-center gap-2.5">
                        <ChevronRight className="w-3.5 h-3.5 text-gray-400" />
                        <Folder className="w-4 h-4 text-gray-500" />
                        <span className="text-sm text-gray-600">{subCategory.name}</span>
                      </div>
                      <span className="text-xs text-gray-500">{subCategory.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Rule Editor */}
      <div className="flex-1 flex flex-col bg-white border-r border-gray-200">
        <div className="h-16 px-4 border-b border-gray-200 flex items-center">
          <h2 className="text-lg font-medium text-gray-900">tainted-sql-from-http-request</h2>
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
          <h2 className="text-lg font-medium text-gray-900">Test Code</h2>
          <Button onClick={runSemgrep} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700" size="sm">
            <Play className="w-4 h-4 mr-1" />
            {isRunning ? "Running..." : "Run"}
          </Button>
        </div>
        <div className="flex-1 p-4 overflow-auto bg-gray-50">
          <div className="h-full bg-white rounded border border-gray-200 p-4 overflow-auto">
            <JavaHighlighter content={codeContent} highlightedLines={highlightedLines} />
          </div>
        </div>
      </div>
    </div>
  )
}
