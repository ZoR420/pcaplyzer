'use client'

import { ScrollArea } from "@/app/components/ui/scroll-area"

interface ResultsDisplayProps {
  results: any | null
}

export default function ResultsDisplay({ results }: ResultsDisplayProps) {
  if (!results) {
    return (
      <div className="text-center text-gray-500 py-8">
        No analysis results yet. Upload a file and select analysis options to begin.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-medium">Analysis Results</h3>
      <ScrollArea className="h-[300px] rounded-md border p-4">
        <div className="space-y-4">
          {Object.entries(results).map(([key, value]) => (
            <div key={key} className="space-y-2">
              <h4 className="font-medium capitalize">{key.replace(/-/g, ' ')}</h4>
              <pre className="bg-gray-50 p-2 rounded text-sm overflow-x-auto">
                {JSON.stringify(value, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  )
} 