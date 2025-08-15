"use client"

import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Search, ChevronRight, ChevronDown } from "lucide-react"

interface SidebarProps {
  selectedRule: string
  onRuleSelect: (rule: string) => void
}

const libraryData = [
  { name: "lesliesec", count: 2, expanded: false },
  {
    name: "Semgrep Registry",
    count: 2022,
    expanded: true,
    children: [
      { name: "ai", count: 25 },
      { name: "apex", count: 18 },
      { name: "bash", count: 7 },
      { name: "c", count: 16 },
      { name: "clojure", count: 5 },
      { name: "csharp", count: 52 },
      { name: "dockerfile", count: 37 },
      { name: "elixir", count: 7 },
      { name: "generic", count: 257 },
      { name: "go", count: 81 },
      { name: "html", count: 6 },
      { name: "java", count: 130 },
      { name: "javascript", count: 182 },
      { name: "json", count: 4 },
      { name: "kotlin", count: 14 },
      { name: "ocaml", count: 33 },
      { name: "php", count: 64 },
      { name: "problem-based-packs", count: 37 },
      { name: "python", count: 378 },
      { name: "ruby", count: 94 },
      { name: "rust", count: 10 },
      { name: "scala", count: 27 },
      { name: "solidity", count: 50 },
      { name: "swift", count: 4 },
      { name: "template", count: 1 },
      { name: "terraform", count: 364 },
    ],
  },
]

export function Sidebar({ selectedRule, onRuleSelect }: SidebarProps) {
  const [expandedItems, setExpandedItems] = useState<string[]>(["Semgrep Registry"])
  const [searchQuery, setSearchQuery] = useState("")

  const toggleExpanded = (name: string) => {
    setExpandedItems((prev) => (prev.includes(name) ? prev.filter((item) => item !== name) : [...prev, name]))
  }

  return (
    <div className="w-80 bg-gray-50 border-r border-gray-200 flex flex-col">
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-4 h-4 bg-gray-800 rounded-sm flex items-center justify-center">
            <span className="text-white text-xs">≡</span>
          </div>
          <span className="font-semibold text-gray-900">Library</span>
        </div>
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
          <Input
            placeholder="e.g. python.flask"
            className="pl-10"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {libraryData.map((item) => (
          <div key={item.name}>
            <div
              className="flex items-center justify-between px-4 py-2 hover:bg-gray-100 cursor-pointer"
              onClick={() => toggleExpanded(item.name)}
            >
              <div className="flex items-center gap-2">
                {item.children ? (
                  expandedItems.includes(item.name) ? (
                    <ChevronDown className="w-4 h-4" />
                  ) : (
                    <ChevronRight className="w-4 h-4" />
                  )
                ) : (
                  <div className="w-4 h-4" />
                )}
                <span className="text-sm text-gray-700">{item.name}</span>
              </div>
              <span className="text-xs text-gray-500">{item.count}</span>
            </div>

            {item.children && expandedItems.includes(item.name) && (
              <div className="ml-6">
                {item.children.map((child) => (
                  <div
                    key={child.name}
                    className="flex items-center justify-between px-4 py-1 hover:bg-gray-100 cursor-pointer"
                  >
                    <div className="flex items-center gap-2">
                      <ChevronRight className="w-4 h-4" />
                      <span className="text-sm text-gray-600">{child.name}</span>
                    </div>
                    <span className="text-xs text-gray-500">{child.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
