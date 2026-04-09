import { createHash } from 'crypto'
import { execFile } from 'child_process'
import { existsSync } from 'fs'
import { mkdir, readFile, stat, writeFile } from 'fs/promises'
import path from 'path'
import { promisify } from 'util'
import { loadCase, type CaseArtifactRecord } from '@/lib/cases'

const execFileAsync = promisify(execFile)
const EXEC_OPTIONS = { maxBuffer: 20 * 1024 * 1024 }

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
  parser: 'stratoshark-cli' | 'local-text-fallback'
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
      destination: [match[4], match[5]].filter(Boolean).join(':'),
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

function getStratosharkCandidates() {
  return [
    process.env.STRATOSHARK_PATH,
    'stratoshark',
    'stratoshark.exe',
    'C:\\Program Files\\Stratoshark\\stratoshark.exe',
    'C:\\Program Files (x86)\\Stratoshark\\stratoshark.exe'
  ].filter((value): value is string => Boolean(value))
}

async function detectStratosharkCli() {
  for (const candidate of getStratosharkCandidates()) {
    try {
      await execFileAsync(candidate, ['--help'], EXEC_OPTIONS)
      return candidate
    } catch {
      // try next candidate
    }
  }
  return null
}

function tryParseJsonObject(text: string) {
  const trimmed = text.trim()
  if (!trimmed) return null

  try {
    return JSON.parse(trimmed) as Record<string, unknown>
  } catch {
    const firstBrace = trimmed.indexOf('{')
    const lastBrace = trimmed.lastIndexOf('}')
    if (firstBrace >= 0 && lastBrace > firstBrace) {
      try {
        return JSON.parse(trimmed.slice(firstBrace, lastBrace + 1)) as Record<string, unknown>
      } catch {
        return null
      }
    }
    return null
  }
}

function buildSummaryFromCli(
  cliData: Record<string, unknown>,
  artifactId: string,
  caseId: string,
  artifact: CaseArtifactRecord,
  sha256: string,
  fileSizeBytes: number
): ScapSummary {
  const processes = Array.isArray(cliData.processTree) ? cliData.processTree : Array.isArray(cliData.processes) ? cliData.processes : []
  const network = Array.isArray(cliData.networkActivity) ? cliData.networkActivity : Array.isArray(cliData.network) ? cliData.network : []
  const files = Array.isArray(cliData.fileActivity) ? cliData.fileActivity : Array.isArray(cliData.files) ? cliData.files : []

  return {
    artifactId,
    caseId,
    sourcePath: artifact.storedRelativePath,
    generatedAt: new Date().toISOString(),
    sha256,
    fileSizeBytes,
    parser: 'stratoshark-cli',
    processTree: processes.map((entry) => {
      const item = entry as Record<string, unknown>
      return {
        pid: String(item.pid ?? item.processId ?? 'unknown'),
        name: String(item.name ?? item.image ?? 'unknown'),
        commandLine: typeof item.commandLine === 'string' ? item.commandLine : undefined,
        parentPid: item.parentPid !== undefined ? String(item.parentPid) : undefined
      }
    }),
    networkActivity: network.map((entry) => {
      const item = entry as Record<string, unknown>
      return {
        timestamp: typeof item.timestamp === 'string' ? item.timestamp : undefined,
        protocol: typeof item.protocol === 'string' ? item.protocol : undefined,
        source: typeof item.source === 'string' ? item.source : undefined,
        destination: typeof item.destination === 'string' ? item.destination : undefined,
        port: item.port !== undefined ? String(item.port) : undefined,
        processPid: item.processPid !== undefined ? String(item.processPid) : undefined
      }
    }),
    fileActivity: files.map((entry) => {
      const item = entry as Record<string, unknown>
      return {
        timestamp: typeof item.timestamp === 'string' ? item.timestamp : undefined,
        path: typeof item.path === 'string' ? item.path : undefined,
        operation: typeof item.operation === 'string' ? item.operation : undefined,
        processPid: item.processPid !== undefined ? String(item.processPid) : undefined
      }
    }),
    notes: ['Generated via Stratoshark CLI adapter.']
  }
}

async function tryGenerateViaStratosharkCli(caseId: string, artifactId: string, artifact: CaseArtifactRecord, artifactPath: string, sha256: string, fileSizeBytes: number) {
  const binary = await detectStratosharkCli()
  if (!binary) {
    return null
  }

  const commandSets = [
    ['export', '--input', artifactPath, '--format', 'json'],
    ['analyze', '--input', artifactPath, '--output', 'json'],
    ['--input', artifactPath, '--json']
  ]

  for (const args of commandSets) {
    try {
      const { stdout } = await execFileAsync(binary, args, EXEC_OPTIONS)
      const parsed = tryParseJsonObject(stdout)
      if (parsed) {
        return buildSummaryFromCli(parsed, artifactId, caseId, artifact, sha256, fileSizeBytes)
      }
    } catch {
      // try next invocation form
    }
  }

  return null
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
  const fileStats = await stat(artifactPath)
  const sha256 = computeSha256(raw)

  const cliSummary = await tryGenerateViaStratosharkCli(caseId, artifactId, artifact, artifactPath, sha256, fileStats.size)
  const summary: ScapSummary = cliSummary || {
    artifactId,
    caseId,
    sourcePath: artifact.storedRelativePath,
    generatedAt: new Date().toISOString(),
    sha256,
    fileSizeBytes: fileStats.size,
    parser: 'local-text-fallback',
    processTree: parseScapText(raw.toString('utf8')).processTree,
    networkActivity: parseScapText(raw.toString('utf8')).networkActivity,
    fileActivity: parseScapText(raw.toString('utf8')).fileActivity,
    notes: [
      'Stratoshark CLI not detected or did not return parseable JSON.',
      ...parseScapText(raw.toString('utf8')).notes
    ]
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
