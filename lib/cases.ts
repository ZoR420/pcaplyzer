import { randomUUID } from 'crypto'
import { existsSync } from 'fs'
import { mkdir, readFile, readdir, stat, writeFile } from 'fs/promises'
import path from 'path'

export const CASE_FILE_EXTENSIONS = ['.pcap', '.pcapng', '.scap'] as const
export type CaseArtifactKind = 'pcap' | 'pcapng' | 'scap'

export type CaseArtifactRecord = {
  id: string
  caseId: string
  kind: CaseArtifactKind
  originalName: string
  storedName: string
  storedRelativePath: string
  sizeBytes: number
  createdAt: string
}

export type CaseRecord = {
  id: string
  title: string
  createdAt: string
  updatedAt: string
  artifacts: CaseArtifactRecord[]
}

const EXTENSION_KIND_MAP: Record<(typeof CASE_FILE_EXTENSIONS)[number], CaseArtifactKind> = {
  '.pcap': 'pcap',
  '.pcapng': 'pcapng',
  '.scap': 'scap'
}

function getCasesRoot() {
  return path.join(process.cwd(), 'cases')
}

function getCaseDir(caseId: string) {
  return path.join(getCasesRoot(), caseId)
}

function getCaseFilePath(caseId: string) {
  return path.join(getCaseDir(caseId), 'case.json')
}

function getArtifactsDir(caseId: string) {
  return path.join(getCaseDir(caseId), 'artifacts')
}

export function getAllowedCaseExtensions() {
  return [...CASE_FILE_EXTENSIONS]
}

export function getArtifactExtension(fileName: string) {
  return path.extname(fileName).toLowerCase() as (typeof CASE_FILE_EXTENSIONS)[number] | string
}

export function assertCaseArtifactExtension(fileName: string) {
  const extension = getArtifactExtension(fileName)
  if (!CASE_FILE_EXTENSIONS.includes(extension as (typeof CASE_FILE_EXTENSIONS)[number])) {
    throw new Error('Invalid file type. Only .pcap, .pcapng, and .scap files are supported')
  }

  return extension as (typeof CASE_FILE_EXTENSIONS)[number]
}

export async function ensureCasesRoot() {
  await mkdir(getCasesRoot(), { recursive: true })
}

export async function createCase(title?: string) {
  await ensureCasesRoot()
  const now = new Date().toISOString()
  const id = randomUUID()
  const record: CaseRecord = {
    id,
    title: title?.trim() || `Case ${now}`,
    createdAt: now,
    updatedAt: now,
    artifacts: []
  }

  await mkdir(getArtifactsDir(id), { recursive: true })
  await writeFile(getCaseFilePath(id), JSON.stringify(record, null, 2), 'utf8')
  return record
}

export async function loadCase(caseId: string) {
  const caseFile = getCaseFilePath(caseId)
  if (!existsSync(caseFile)) {
    throw new Error('Case not found')
  }

  const raw = await readFile(caseFile, 'utf8')
  return JSON.parse(raw) as CaseRecord
}

export async function saveCase(record: CaseRecord) {
  const updated: CaseRecord = {
    ...record,
    updatedAt: new Date().toISOString()
  }
  await writeFile(getCaseFilePath(record.id), JSON.stringify(updated, null, 2), 'utf8')
  return updated
}

export async function listCases() {
  await ensureCasesRoot()
  const entries = await readdir(getCasesRoot(), { withFileTypes: true })
  const cases: CaseRecord[] = []

  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const caseFile = getCaseFilePath(entry.name)
    if (!existsSync(caseFile)) continue
    const raw = await readFile(caseFile, 'utf8')
    cases.push(JSON.parse(raw) as CaseRecord)
  }

  return cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
}

export async function addArtifactToCase(caseId: string, file: File) {
  const record = await loadCase(caseId)
  const extension = assertCaseArtifactExtension(file.name)
  const artifactId = randomUUID()
  const storedName = `${artifactId}${extension}`
  const relativePath = path.join('artifacts', storedName)
  const absolutePath = path.join(getCaseDir(caseId), relativePath)
  const bytes = await file.arrayBuffer()

  await mkdir(getArtifactsDir(caseId), { recursive: true })
  await writeFile(absolutePath, Buffer.from(bytes))

  const artifact: CaseArtifactRecord = {
    id: artifactId,
    caseId,
    kind: EXTENSION_KIND_MAP[extension],
    originalName: file.name,
    storedName,
    storedRelativePath: relativePath,
    sizeBytes: file.size,
    createdAt: new Date().toISOString()
  }

  record.artifacts.push(artifact)
  const saved = await saveCase(record)
  return { caseRecord: saved, artifact }
}

export async function getCaseArtifactStats(caseId: string) {
  const record = await loadCase(caseId)
  const stats = await Promise.all(record.artifacts.map(async (artifact) => {
    const artifactPath = path.join(getCaseDir(caseId), artifact.storedRelativePath)
    const fileStats = await stat(artifactPath)
    return { ...artifact, sizeBytes: fileStats.size }
  }))

  return { ...record, artifacts: stats }
}
