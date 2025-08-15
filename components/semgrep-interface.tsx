"use client"

import { useState } from "react"
import { Header } from "./header"
import { Sidebar } from "./sidebar"
import { MainContent } from "./main-content"
import { CodeEditor } from "./code-editor"

export function SemgrepInterface() {
  const [selectedRule, setSelectedRule] = useState("tainted-sql-from-http-request")
  const [activeTab, setActiveTab] = useState("structure")

  return (
    <div className="h-screen flex flex-col bg-background">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar selectedRule={selectedRule} onRuleSelect={setSelectedRule} />
        <MainContent selectedRule={selectedRule} activeTab={activeTab} onTabChange={setActiveTab} />
        <CodeEditor />
      </div>
    </div>
  )
}
