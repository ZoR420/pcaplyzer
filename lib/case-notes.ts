import { existsSync } from 'fs'
import { mkdir, readFile, writeFile } from 'fs/promises'
import path from 'path'

export type CaseNote = {
  id: string
  createdAt: string
  content: string
}

function getNotesPath(caseId: string) {
  return path.join(process.cwd(), 'cases', caseId, 'notes.json')
}

export async function readCaseNotes(caseId: string) {
  const notesPath = getNotesPath(caseId)
  if (!existsSync(notesPath)) {
    return [] as CaseNote[]
  }

  const raw = await readFile(notesPath, 'utf8')
  return JSON.parse(raw) as CaseNote[]
}

export async function addCaseNote(caseId: string, content: string) {
  const notesPath = getNotesPath(caseId)
  await mkdir(path.dirname(notesPath), { recursive: true })
  const notes = await readCaseNotes(caseId)
  const note: CaseNote = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    content: content.trim()
  }
  notes.unshift(note)
  await writeFile(notesPath, JSON.stringify(notes, null, 2), 'utf8')
  return note
}
