import { createHash } from 'crypto'
import { existsSync } from 'fs'
import { mkdir, readFile, stat, writeFile } from 'fs/promises'
import path from 'path'
import { loadCase, type CaseArtifactRecord } from '@/lib/cases'

export type ScapProcessNode = {
  pid: string
  name: string
  commandLine?: string
  parentPid?: string
}

export type ScapNetworkActivity = {
  timestamp?: string
  protocol?: string
  source?: string
  destination?: string
  port?: string
  processPid?: string
}

export type ScapFileActivity = {
  timestamp?: string
  path?: string
  operation?: string
  processPid?: string
}

export type ScapSummary = {
  artifactId: string
  caseId: string
  sourcePath: string
  generatedAt: string
  sha256: string
  fileSizeBytes: number
  parser: 'local-text-fallback'
  processTree: ScapProcessNode[]
  networkActivity: ScapNetworkActivity[]
  fileActivity: ScapFileActivity[]
  notes: string[]
}

function getCaseRoot(caseId: string) {
  return path.join(process.cwd(), 'cases', caseId)
}

function getArtifactAbsolutePath(caseId: string, artifact: CaseArtifactRecord) {
  return path.join(getCaseRoot(caseId), artifact.storedRelativePath)
}

function getDerivedDir(caseId: string, artifactId: string) {
  return path.join(getCaseRoot(caseId), 'derived', artifactId)
}

export function getScapSummaryPath(caseId: string, artifactId: string) {
  return path.join(getDerivedDir(caseId, artifactId), 'scap-summary.json')
}

function computeSha256(content: Buffer) {
  return createHash('sha256').update(content).digest('hex')
}

function collectMatches(text: string, regex: RegExp, mapper: (match: RegExpExecArray) => Record<string, string | undefined>) {
  const results: Record<string, string | undefined>[] = []
  let match: RegExpExecArray | null
  const localRegex = new RegExp(regex.source, regex.flags)
  while ((match = localRegex.exec(text)) !== null) {
    results.push(mapper(match))
    if (!localRegex.global) break
  }
  return results
}

function parseScapText(text: string) {
  const processTree = collectMatches(
    text,
    /(pid|processid|process_id)[:=\s]+(\d+).*?(name|image|processname)[:=\s]+([^\r\n]+)/gim,
    (match) => ({ pid: match[2], name: match[4]?.trim() })
  ).map((entry) => ({
    pid: entry.pid || 'unknown',
    name: entry.name || 'unknown'
  }))

  const networkActivity = collectMatches(
    text,
    /(tcp|udp|icmp)\s+([0-9a-f:.]+)[:]?([0-9]*)\s*(?:->|to)\s*([0-9a-f:.]+)[:]?([0-9]*)/gim,
    (match) => ({
      protocol: match[1]?.toUpperCase(),
      source: [match[2], match[3]].filter(Boolean).join(':'),
      destination: [match[4], match[5]].filter(Boolean).join(':')
    })
  ).map((entry) => ({
    protocol: entry.protocol,
    source: entry.source,
    destination: entry.destination,
    port: entry.destination?.split(':')[1]
  }))

  const fileActivity = collectMatches(
    text,
    /(create|write|delete|open|read)\s+(?:file[:=\s]+)?([^\r\n]+)/gim,
    (match) => ({ operation: match[1]?.toUpperCase(), path: match[2]?.trim() })
  ).map((entry) => ({
    operation: entry.operation,
    path: entry.path
  }))

  const notes: string[] = []
  if (processTree.length === 0) notes.push('No process entries extracted by fallback text parser.')
  if (networkActivity.length === 0) notes.push('No network entries extracted by fallback text parser.')
  if (fileActivity.length === 0) notes.push('No file activity extracted by fallback text parser.')

  return { processTree, networkActivity, fileActivity, notes }
}

export async function generateScapSummary(caseId: string, artifactId: string) {
  const caseRecord = await loadCase(caseId)
  const artifact = caseRecord.artifacts.find((entry) => entry.id === artifactId)
  if (!artifact) {
    throw new Error('Artifact not found')
  }
  if (artifact.kind !== 'scap') {
    throw new Error('Artifact is not a SCAP file')
  }

  const artifactPath = getArtifactAbsolutePath(caseId, artifact)
  if (!existsSync(artifactPath)) {
    throw new Error('Artifact file not found')
  }

  const raw = await readFile(artifactPath)
  const parsed = parseScapText(raw.toString('utf8'))
  const fileStats = await stat(artifactPath)
  const summary: ScapSummary = {
    artifactId,
    caseId,
    sourcePath: artifact.storedRelativePath,
    generatedAt: new Date().toISOString(),
    sha256: computeSha256(raw),
    fileSizeBytes: fileStats.size,
    parser: 'local-text-fallback',
    processTree: parsed.processTree,
    networkActivity: parsed.networkActivity,
    fileActivity: parsed.fileActivity,
    notes: parsed.notes
  }

  const outputDir = getDerivedDir(caseId, artifactId)
  await mkdir(outputDir, { recursive: true })
  await writeFile(getScapSummaryPath(caseId, artifactId), JSON.stringify(summary, null, 2), 'utf8')
  return summary
}

export async function readScapSummary(caseId: string, artifactId: string) {
  const summaryPath = getScapSummaryPath(caseId, artifactId)
  if (!existsSync(summaryPath)) {
    return null
  }

  const raw = await readFile(summaryPath, 'utf8')
  return JSON.parse(raw) as ScapSummary
}
