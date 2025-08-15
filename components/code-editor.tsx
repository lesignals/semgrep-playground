"use client"

import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"

const tabs = [
  { id: "test-code", label: "test code" },
  { id: "live-code", label: "live code", badge: "NEW" },
  { id: "metadata", label: "metadata" },
  { id: "docs", label: "docs" },
]

export function CodeEditor() {
  const [activeTab, setActiveTab] = useState("test-code")
  const [showNotification, setShowNotification] = useState(true)

  const javaCode = `/**
 * OWASP Benchmark v1.2
 *
 * This file is part of the Open Web Application Security Project (OWASP) Benchmark
 * Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>
 *.
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
public class BenchmarkTest00001 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        doPost(request, response);
    }`

  return (
    <div className="w-1/2 bg-white border-l border-gray-200 flex flex-col">
      <div className="border-b border-gray-200 px-4 py-2">
        <div className="flex gap-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
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

      <div className="flex-1 relative">
        {showNotification && (
          <div className="absolute top-4 right-4 z-10 bg-orange-500 text-white p-3 rounded-lg shadow-lg max-w-sm">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-medium text-sm">Dependency paths are not loading for Supply Chain</div>
                <div className="text-xs opacity-90 mt-1">Last updated 7 hours ago</div>
                <Button variant="link" className="text-white underline p-0 h-auto text-xs mt-1">
                  View latest updates
                </Button>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="text-white hover:bg-orange-600 p-1 h-auto"
                onClick={() => setShowNotification(false)}
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}

        <div className="h-full overflow-y-auto">
          <div className="flex">
            <div className="w-12 bg-gray-50 border-r border-gray-200 text-right pr-2 py-4 text-xs text-gray-500 font-mono">
              {Array.from({ length: 50 }, (_, i) => (
                <div key={i + 1} className="leading-6">
                  {i + 1}
                </div>
              ))}
            </div>
            <div className="flex-1 p-4">
              <pre className="text-sm font-mono text-gray-800 leading-6">
                <code>{javaCode}</code>
              </pre>
            </div>
          </div>
        </div>

        <div className="absolute bottom-4 right-4 text-sm text-gray-500">Run your rule to see matches.</div>
      </div>
    </div>
  )
}
