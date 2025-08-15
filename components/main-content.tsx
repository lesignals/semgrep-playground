"use client"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Plus, Filter, ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"

interface MainContentProps {
  selectedRule: string
  activeTab: string
  onTabChange: (tab: string) => void
}

const tabs = [
  { id: "structure", label: "structure", badge: "NEW" },
  { id: "advanced", label: "advanced" },
  { id: "test-code", label: "test code" },
  { id: "live-code", label: "live code", badge: "NEW" },
  { id: "metadata", label: "metadata" },
  { id: "docs", label: "docs" },
]

export function MainContent({ selectedRule, activeTab, onTabChange }: MainContentProps) {
  return (
    <div className="flex-1 flex flex-col bg-white">
      <div className="border-b border-gray-200 px-6 py-4">
        <h1 className="text-xl font-semibold text-gray-900 mb-4">{selectedRule}</h1>
        <div className="flex gap-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "pb-2 border-b-2 text-sm font-medium flex items-center gap-2",
                activeTab === tab.id
                  ? "border-blue-500 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700",
              )}
            >
              {tab.label}
              {tab.badge && (
                <Badge variant="secondary" className="text-xs bg-blue-100 text-blue-700">
                  {tab.badge}
                </Badge>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 p-6 overflow-y-auto">
        {activeTab === "structure" && <StructureTab />}
        {activeTab === "advanced" && <AdvancedTab />}
        {activeTab === "test-code" && <div className="text-gray-500">Test code content...</div>}
        {activeTab === "live-code" && <div className="text-gray-500">Live code content...</div>}
        {activeTab === "metadata" && <div className="text-gray-500">Metadata content...</div>}
        {activeTab === "docs" && <div className="text-gray-500">Documentation content...</div>}
      </div>
    </div>
  )
}

function StructureTab() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 mb-6">
        <Input placeholder="search" className="flex-1" />
        <Button className="bg-blue-600 hover:bg-blue-700">taint</Button>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Sources</h3>
          <div className="border border-gray-200 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-sm text-gray-600">pattern</span>
              <Filter className="w-4 h-4 text-gray-400" />
              <Plus className="w-4 h-4 text-gray-400" />
            </div>
            <Input placeholder="Enter a pattern here..." />
          </div>
        </div>

        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Sinks</h3>
          <div className="border border-gray-200 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-sm text-gray-600">pattern</span>
              <Filter className="w-4 h-4 text-gray-400" />
              <Plus className="w-4 h-4 text-gray-400" />
            </div>
            <Input placeholder="Enter a pattern here..." />
          </div>
        </div>

        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Sanitizers</h3>
          <Button className="bg-blue-600 hover:bg-blue-700">Add Sanitizers</Button>
        </div>

        <div className="border-t border-gray-200 pt-6">
          <div className="flex items-center gap-2 mb-4">
            <ChevronDown className="w-4 h-4" />
            <h3 className="text-lg font-semibold text-gray-900">Rule info</h3>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Rule ID</label>
              <Input value="tainted-sql-from-http-request" readOnly />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Language</label>
              <Select defaultValue="java">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="java">Java</SelectItem>
                  <SelectItem value="python">Python</SelectItem>
                  <SelectItem value="javascript">JavaScript</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
              <Select defaultValue="error">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="error">ERROR</SelectItem>
                  <SelectItem value="warning">WARNING</SelectItem>
                  <SelectItem value="info">INFO</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Message</label>
              <Textarea value="This rule is deprecated" className="min-h-[60px]" />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function AdvancedTab() {
  const yamlContent = `rules:
  - id: tainted-sql-from-http-request
    message: This rule is deprecated
    severity: CRITICAL
    metadata:
      likelihood: HIGH
      impact: HIGH
      confidence: MEDIUM
      category: security
      subcategory:
        - vuln
    cwe:
      - "CWE-89: Improper Neutralization of Special Elements used in an SQL
        Command ('SQL Injection')"
    cwe2021-top25: true
    cwe2022-top25: true
    owasp:
      - A03:2017 - Injection
      - A03:2021 - Injection
    references:
      - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.
        html
      - https://owasp.org/www-community/attacks/SQL_Injection
    technology:
      - sql
      - java
      - servlets
      - spring
    license: Semgrep Rules License v1.0. For more details, visit
      semgrep.dev/legal/rules-license
    vulnerability_class:
      - SQL Injection
    languages:
      - java
    min-version: 1.71.0
    patterns:
      - pattern: a()
      - pattern: b()`

  return (
    <div className="h-full">
      <pre className="text-sm font-mono text-gray-800 whitespace-pre-wrap leading-relaxed">{yamlContent}</pre>
    </div>
  )
}
