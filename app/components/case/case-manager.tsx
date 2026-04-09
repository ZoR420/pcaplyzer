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

type ScapSummary = {
  parser?: 'stratoshark-cli' | 'local-text-fallback'
  processTree: Array<{ pid: string; name: string }>
  networkActivity: Array<{ protocol?: string; source?: string; destination?: string }>
  fileActivity: Array<{ operation?: string; path?: string }>
  notes: string[]
}

type ExportedCasePayload = {
  case: CaseRecord
  derivedArtifacts: Array<{
    artifactId: string
    kind: 'pcap' | 'pcapng' | 'scap'
    summary: unknown
  }>
  exportedAt: string
}

type CorrelatedCaseView = {
  timeline: Array<{
    artifactId: string
    artifactKind: 'pcap' | 'pcapng' | 'scap'
    category: 'process' | 'network' | 'file' | 'note'
    timestamp: string | null
    summary: string
  }>
  processNetworkMap: Array<{
    processPid: string
    processName: string
    networkEvents: Array<{ protocol?: string; source?: string; destination?: string; timestamp?: string }>
  }>
  guidedTriage: string[]
}

type CaseNote = {
  id: string
  createdAt: string
  content: string
}

type CaseReport = {
  report: {
    notes: CaseNote[]
    guidedTriage: string[]
    timelinePreview: Array<{ summary: string; timestamp: string | null; category: string }>
    generatedAt: string
  }
}

type CaseFindings = {
  findings: {
    findings: Array<{
      id: string
      title: string
      severity: 'low' | 'medium' | 'high'
      category: 'network' | 'file' | 'process' | 'behavior'
      summary: string
      iocs: string[]
    }>
    iocs: string[]
    score: number
    severity: 'low' | 'medium' | 'high'
    generatedAt: string
  }
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
  const [scapSummaries, setScapSummaries] = useState<Record<string, ScapSummary>>({})
  const [exportPreview, setExportPreview] = useState<ExportedCasePayload | null>(null)
  const [correlation, setCorrelation] = useState<CorrelatedCaseView | null>(null)
  const [notes, setNotes] = useState<CaseNote[]>([])
  const [noteDraft, setNoteDraft] = useState('')
  const [reportPreview, setReportPreview] = useState<CaseReport | null>(null)
  const [findingsPreview, setFindingsPreview] = useState<CaseFindings | null>(null)

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





  async function loadCaseNotes() {
    if (!selectedCaseId) return

    const response = await fetch(`/api/cases/${selectedCaseId}/notes`)
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Failed to load notes')
    setNotes(data.notes || [])
  }

  async function saveCaseNote() {
    if (!selectedCaseId || !noteDraft.trim()) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: noteDraft })
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to save note')
      setNoteDraft('')
      await loadCaseNotes()
      setStatus('Case note saved')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to save note')
    } finally {
      setLoading(false)
    }
  }


  async function loadCaseFindings() {
    if (!selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/findings`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to load findings')
      setFindingsPreview(data)
      setStatus('Findings generated')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }

  async function loadCaseReport() {
    if (!selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/report`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to load report')
      setReportPreview(data)
      setStatus('Case report generated')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to load report')
    } finally {
      setLoading(false)
    }
  }

  async function loadCorrelationView() {
    if (!selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/correlate`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to load case correlation')
      setCorrelation(data.correlation)
      setStatus('Correlation view loaded')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to load case correlation')
    } finally {
      setLoading(false)
    }
  }

  async function exportSelectedCase() {
    if (!selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/export`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to export case')
      setExportPreview(data)
      setStatus('Case export generated')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to export case')
    } finally {
      setLoading(false)
    }
  }

  async function generateScapArtifactSummary(artifactId: string) {
    if (!selectedCaseId) return

    setLoading(true)
    setStatus(null)
    try {
      const response = await fetch(`/api/cases/${selectedCaseId}/artifacts/${artifactId}/scap-summary`, {
        method: 'POST'
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to generate SCAP summary')
      setScapSummaries((prev) => ({ ...prev, [artifactId]: data.summary }))
      setStatus('Generated SCAP summary')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Failed to generate SCAP summary')
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
                <div className="flex gap-2">
                  <Button type="button" variant="outline" onClick={exportSelectedCase} disabled={loading}>
                    Export case
                  </Button>
                  <Button type="button" variant="outline" onClick={loadCorrelationView} disabled={loading}>
                    Correlate
                  </Button>
                  <Button type="button" variant="outline" onClick={loadCaseReport} disabled={loading}>
                    Report
                  </Button>
                  <Button type="button" variant="outline" onClick={loadCaseFindings} disabled={loading}>
                    Findings
                  </Button>
                  <label className="inline-flex cursor-pointer items-center rounded-md border px-3 py-2 text-sm hover:bg-gray-50">
                    Add artifact
                    <input type="file" accept={ACCEPTED_EXTENSIONS} className="hidden" onChange={handleArtifactUpload} />
                  </label>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                <div className="space-y-2">
                {selectedCase.artifacts.map((artifact) => (
                  <div key={artifact.id} className="rounded-md border bg-gray-50 px-3 py-2 text-sm">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium">{artifact.originalName}</div>
                        <div className="text-xs text-gray-500">
                          {artifact.kind.toUpperCase()} · {formatBytes(artifact.sizeBytes)} · {new Date(artifact.createdAt).toLocaleString()}
                        </div>
                      </div>
                      {artifact.kind === 'scap' ? (
                        <Button type="button" variant="outline" onClick={() => generateScapArtifactSummary(artifact.id)} disabled={loading}>
                          Generate summary
                        </Button>
                      ) : null}
                    </div>
                    {artifact.kind === 'scap' && scapSummaries[artifact.id] ? (() => {
                      const summary = scapSummaries[artifact.id]
                      if (!summary) return null
                      return (
                        <div className="mt-3 rounded border bg-white p-3 text-xs text-gray-700">
                          <div>Parser: {summary.parser || 'unknown'}</div>
                          <div>Processes: {summary.processTree.length}</div>
                          <div>Network events: {summary.networkActivity.length}</div>
                          <div>File events: {summary.fileActivity.length}</div>
                          {summary.notes.length ? (
                            <div className="mt-2 text-amber-700">{summary.notes.join(' ')}</div>
                          ) : null}
                        </div>
                      )
                    })() : null}
                  </div>
                ))}
                {selectedCase.artifacts.length === 0 ? <div className="text-sm text-gray-500">No artifacts in this case yet.</div> : null}
                </div>
                <div className="rounded-md border bg-white p-3 text-sm">
                  <h4 className="mb-3 font-medium">Unified case view</h4>
                  {selectedCase.artifacts.length === 0 ? (
                    <div className="text-sm text-gray-500">Add PCAP or SCAP artifacts to compare them here.</div>
                  ) : (
                    <div className="space-y-3">
                      {selectedCase.artifacts.map((artifact) => (
                        <div key={`summary-${artifact.id}`} className="rounded border bg-gray-50 p-3">
                          <div className="font-medium">{artifact.originalName}</div>
                          <div className="text-xs text-gray-500">{artifact.kind.toUpperCase()}</div>
                          {artifact.kind === 'scap' && scapSummaries[artifact.id] ? (
                            <div className="mt-2 space-y-1 text-xs text-gray-700">
                              <div>Processes: {scapSummaries[artifact.id]?.processTree.length || 0}</div>
                              <div>Network events: {scapSummaries[artifact.id]?.networkActivity.length || 0}</div>
                              <div>File events: {scapSummaries[artifact.id]?.fileActivity.length || 0}</div>
                            </div>
                          ) : artifact.kind === 'scap' ? (
                            <div className="mt-2 text-xs text-amber-700">Generate SCAP summary to populate this view.</div>
                          ) : (
                            <div className="mt-2 text-xs text-gray-600">PCAP artifact ready for future unified views/export.</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {exportPreview ? (
                    <div className="mt-4 rounded border bg-gray-50 p-3 text-xs text-gray-700">
                      <div className="font-medium">Export preview</div>
                      <div>Artifacts: {exportPreview.case.artifacts.length}</div>
                      <div>Derived summaries: {exportPreview.derivedArtifacts.length}</div>
                      <div>Generated: {new Date(exportPreview.exportedAt).toLocaleString()}</div>
                    </div>
                  ) : null}

                  {correlation ? (
                    <div className="mt-4 rounded border bg-gray-50 p-3 text-xs text-gray-700">
                      <div className="font-medium">Guided triage</div>
                      <ul className="mt-2 list-disc space-y-1 pl-4">
                        {correlation.guidedTriage.map((item, index) => (
                          <li key={`triage-${index}`}>{item}</li>
                        ))}
                      </ul>
                      <div className="mt-3 font-medium">Timeline</div>
                      <div className="mt-2 max-h-40 space-y-2 overflow-auto">
                        {correlation.timeline.slice(0, 8).map((event, index) => (
                          <div key={`timeline-${index}`} className="rounded border bg-white p-2">
                            <div className="font-medium">{event.category.toUpperCase()}</div>
                            <div>{event.summary}</div>
                            <div className="text-[11px] text-gray-500">{event.timestamp || 'No timestamp'}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="mt-4 rounded border bg-gray-50 p-3 text-xs text-gray-700">
                    <div className="font-medium">Case notes</div>
                    <div className="mt-2 space-y-2">
                      <textarea
                        value={noteDraft}
                        onChange={(event) => setNoteDraft(event.target.value)}
                        placeholder="Add analyst notes, findings, or follow-ups..."
                        className="min-h-[80px] w-full rounded border p-2 text-sm"
                      />
                      <Button type="button" variant="outline" onClick={saveCaseNote} disabled={loading || !noteDraft.trim()}>
                        Save note
                      </Button>
                    </div>
                    <div className="mt-3 max-h-40 space-y-2 overflow-auto">
                      {notes.length === 0 ? <div className="text-gray-500">No notes yet.</div> : notes.map((note) => (
                        <div key={note.id} className="rounded border bg-white p-2">
                          <div>{note.content}</div>
                          <div className="mt-1 text-[11px] text-gray-500">{new Date(note.createdAt).toLocaleString()}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {reportPreview ? (
                    <div className="mt-4 rounded border bg-gray-50 p-3 text-xs text-gray-700">
                      <div className="font-medium">Report preview</div>
                      <div>Generated: {new Date(reportPreview.report.generatedAt).toLocaleString()}</div>
                      <div>Notes: {reportPreview.report.notes.length}</div>
                      <div>Triage items: {reportPreview.report.guidedTriage.length}</div>
                    </div>
                  ) : null}

                  {findingsPreview ? (
                    <div className="mt-4 rounded border bg-gray-50 p-3 text-xs text-gray-700">
                      <div className="font-medium">Findings summary</div>
                      <div>Severity: {findingsPreview.findings.severity.toUpperCase()}</div>
                      <div>Score: {findingsPreview.findings.score}</div>
                      <div>IOCs: {findingsPreview.findings.iocs.length}</div>
                      <div className="mt-2 space-y-2">
                        {findingsPreview.findings.findings.map((finding) => (
                          <div key={finding.id} className="rounded border bg-white p-2">
                            <div className="font-medium">{finding.title}</div>
                            <div>{finding.summary}</div>
                            <div className="text-[11px] text-gray-500">{finding.severity.toUpperCase()} • {finding.category}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
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
