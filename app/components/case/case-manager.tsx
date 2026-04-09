'use client'

import { useCallback, useEffect, useState } from 'react'
import { Button } from '@/app/components/ui/button'
import { Card } from '@/app/components/ui/card'
import { ScrollArea } from '@/app/components/ui/scroll-area'

type CaseArtifact = {
  id: string
  kind: 'pcap' | 'pcapng' | 'scap'
  originalName: string
  sizeBytes: number
  createdAt: string
}

type CaseRecord = {
  id: string
  title: string
  createdAt: string
  updatedAt: string
  artifacts: CaseArtifact[]
}

const ACCEPTED_EXTENSIONS = '.pcap,.pcapng,.scap'

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 2)} ${units[index]}`
}

export function CaseManager() {
  const [cases, setCases] = useState<CaseRecord[]>([])
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
  const [newCaseTitle, setNewCaseTitle] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const selectedCase = cases.find((entry) => entry.id === selectedCaseId) || null

  const refreshCases = useCallback(async () => {
    const response = await fetch('/api/cases')
    if (!response.ok) return
    const data = await response.json()
    setCases(data.cases || [])
    if (!selectedCaseId && data.cases?.length) {
      setSelectedCaseId(data.cases[0].id)
    }
  }, [selectedCaseId])

  useEffect(() => {
    refreshCases().catch(() => undefined)
  }, [refreshCases])

  async function createNewCase() {
    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: newCaseTitle || undefined })
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to create case')
      setCases((prev) => [data.case, ...prev])
      setSelectedCaseId(data.case.id)
      setNewCaseTitle('')
      setStatus(`Created case ${data.case.title}`)
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to create case')
    } finally {
      setLoading(false)
    }
  }

  async function handleArtifactUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file || !selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(`/api/cases/${selectedCaseId}/artifacts`, {
        method: 'POST',
        body: formData
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to upload artifact')

      setCases((prev) => prev.map((entry) => (entry.id === selectedCaseId ? data.case : entry)))
      setStatus(`Added ${data.artifact.originalName} to case`)
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to upload artifact')
    } finally {
      event.target.value = ''
      setLoading(false)
    }
  }

  return (
    <Card className="p-4">
      <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Case Manager</h2>
          <p className="text-sm text-gray-500">Create local cases and attach PCAP/PCAPNG/SCAP artifacts.</p>
        </div>
        <div className="flex gap-2">
          <input
            value={newCaseTitle}
            onChange={(event) => setNewCaseTitle(event.target.value)}
            placeholder="New case title"
            className="rounded-md border px-3 py-2 text-sm"
          />
          <Button onClick={createNewCase} disabled={loading}>Create Case</Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-[280px_1fr]">
        <ScrollArea className="h-[320px] rounded-md border">
          <div className="space-y-2 p-2">
            {cases.map((entry) => (
              <button
                key={entry.id}
                type="button"
                onClick={() => setSelectedCaseId(entry.id)}
                className={`w-full rounded-md border px-3 py-2 text-left ${selectedCaseId === entry.id ? 'border-blue-500 bg-blue-50' : 'border-transparent hover:bg-gray-50'}`}
              >
                <div className="font-medium">{entry.title}</div>
                <div className="text-xs text-gray-500">{entry.artifacts.length} artifact(s)</div>
              </button>
            ))}
            {cases.length === 0 ? <div className="p-3 text-sm text-gray-500">No cases yet.</div> : null}
          </div>
        </ScrollArea>

        <div className="rounded-md border p-4">
          {selectedCase ? (
            <>
              <div className="mb-4 flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-md font-semibold">{selectedCase.title}</h3>
                  <p className="text-xs text-gray-500">Updated {new Date(selectedCase.updatedAt).toLocaleString()}</p>
                </div>
                <label className="inline-flex cursor-pointer items-center rounded-md border px-3 py-2 text-sm hover:bg-gray-50">
                  Add artifact
                  <input type="file" accept={ACCEPTED_EXTENSIONS} className="hidden" onChange={handleArtifactUpload} />
                </label>
              </div>

              <div className="space-y-2">
                {selectedCase.artifacts.map((artifact) => (
                  <div key={artifact.id} className="rounded-md border bg-gray-50 px-3 py-2 text-sm">
                    <div className="font-medium">{artifact.originalName}</div>
                    <div className="text-xs text-gray-500">
                      {artifact.kind.toUpperCase()} · {formatBytes(artifact.sizeBytes)} · {new Date(artifact.createdAt).toLocaleString()}
                    </div>
                  </div>
                ))}
                {selectedCase.artifacts.length === 0 ? <div className="text-sm text-gray-500">No artifacts in this case yet.</div> : null}
              </div>
            </>
          ) : (
            <div className="text-sm text-gray-500">Create or select a case to attach artifacts.</div>
          )}
        </div>
      </div>

      {status ? <div className="mt-4 text-sm text-gray-600">{status}</div> : null}
    </Card>
  )
}
