import { Button } from "@/components/ui/button"
import { GitFork, Share, Plus, MoreHorizontal } from "lucide-react"

export function Header() {
  return (
    <header className="bg-white border-b border-gray-200 px-4 py-2 flex items-center justify-between">
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-teal-500 rounded flex items-center justify-center">
            <span className="text-white font-bold text-sm">S</span>
          </div>
          <span className="font-semibold text-gray-900">Semgrep</span>
        </div>
        <nav className="flex items-center gap-6">
          <a href="#" className="text-gray-600 hover:text-gray-900">
            Registry
          </a>
          <a href="#" className="text-blue-600 hover:text-blue-700">
            Playground
          </a>
          <a href="#" className="text-gray-600 hover:text-gray-900">
            Products
          </a>
          <a href="#" className="text-gray-600 hover:text-gray-900">
            Pricing
          </a>
          <a href="#" className="text-gray-600 hover:text-gray-900">
            Docs
          </a>
        </nav>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-gray-600">lesliesec</span>
        <Button variant="outline" size="sm">
          <GitFork className="w-4 h-4 mr-1" />
          Fork
        </Button>
        <Button variant="outline" size="sm">
          <Share className="w-4 h-4 mr-1" />
          Share
        </Button>
        <Button size="sm">
          <Plus className="w-4 h-4 mr-1" />
          Add to Policy
        </Button>
        <Button variant="ghost" size="sm">
          <MoreHorizontal className="w-4 h-4" />
        </Button>
      </div>
    </header>
  )
}
