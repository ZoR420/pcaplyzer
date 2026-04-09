import { loadCase, type CaseArtifactRecord } from '@/lib/cases'
import { readScapSummary, type ScapSummary } from '@/lib/scap'

export type TimelineEvent = {
  artifactId: string
  artifactKind: 'pcap' | 'pcapng' | 'scap'
  category: 'process' | 'network' | 'file' | 'note'
  timestamp: string | null
  summary: string
  source?: string
  destination?: string
  processPid?: string
}

export type CorrelatedCaseView = {
  caseId: string
  timeline: TimelineEvent[]
  processNetworkMap: Array<{
    processPid: string
    processName: string
    networkEvents: Array<{
      protocol?: string
      source?: string
      destination?: string
      timestamp?: string
    }>
  }>
  guidedTriage: string[]
}

function toTimelineFromScap(artifact: CaseArtifactRecord, summary: ScapSummary): TimelineEvent[] {
  const processEvents = summary.processTree.map((process) => ({
    artifactId: artifact.id,
    artifactKind: artifact.kind,
    category: 'process' as const,
    timestamp: null,
    summary: `${process.name} (PID ${process.pid})`,
    processPid: process.pid
  }))

  const networkEvents = summary.networkActivity.map((event) => ({
    artifactId: artifact.id,
    artifactKind: artifact.kind,
    category: 'network' as const,
    timestamp: event.timestamp || null,
    summary: `${event.protocol || 'NETWORK'} ${event.source || '?'} -> ${event.destination || '?'}`,
    source: event.source,
    destination: event.destination,
    processPid: event.processPid
  }))

  const fileEvents = summary.fileActivity.map((event) => ({
    artifactId: artifact.id,
    artifactKind: artifact.kind,
    category: 'file' as const,
    timestamp: event.timestamp || null,
    summary: `${event.operation || 'FILE'} ${event.path || ''}`.trim(),
    processPid: event.processPid
  }))

  return [...processEvents, ...networkEvents, ...fileEvents]
}

function buildProcessNetworkMap(summary: ScapSummary) {
  return summary.processTree.map((process) => ({
    processPid: process.pid,
    processName: process.name,
    networkEvents: summary.networkActivity.filter((entry) => entry.processPid === process.pid || !entry.processPid)
  }))
}

function buildGuidedTriage(timeline: TimelineEvent[]) {
  const triage: string[] = []
  const networkEvents = timeline.filter((event) => event.category === 'network')
  const fileEvents = timeline.filter((event) => event.category === 'file')
  const processEvents = timeline.filter((event) => event.category === 'process')

  if (processEvents.length > 0) {
    triage.push(`Review ${processEvents.length} process entries and identify suspicious parents/children.`)
  }
  if (networkEvents.length > 0) {
    triage.push(`Inspect ${networkEvents.length} network events for unusual destinations or beaconing.`)
  }
  if (fileEvents.length > 0) {
    triage.push(`Check ${fileEvents.length} file activity events for dropped binaries or persistence artifacts.`)
  }
  if (triage.length === 0) {
    triage.push('No correlated events yet. Generate artifact summaries first.')
  }

  return triage
}

export async function buildCorrelatedCaseView(caseId: string): Promise<CorrelatedCaseView> {
  const caseRecord = await loadCase(caseId)
  const scapArtifacts = caseRecord.artifacts.filter((artifact) => artifact.kind === 'scap')
  const scapSummaries = await Promise.all(
    scapArtifacts.map(async (artifact) => ({ artifact, summary: await readScapSummary(caseId, artifact.id) }))
  )

  const timeline = scapSummaries.flatMap(({ artifact, summary }) => summary ? toTimelineFromScap(artifact, summary) : [])
  const processNetworkMap = scapSummaries.flatMap(({ summary }) => summary ? buildProcessNetworkMap(summary) : [])

  timeline.sort((a, b) => {
    const left = a.timestamp ? new Date(a.timestamp).getTime() : 0
    const right = b.timestamp ? new Date(b.timestamp).getTime() : 0
    return left - right
  })

  return {
    caseId,
    timeline,
    processNetworkMap,
    guidedTriage: buildGuidedTriage(timeline)
  }
}
