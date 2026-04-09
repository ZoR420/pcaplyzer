import { existsSync } from 'fs'
import { mkdir, readFile, writeFile } from 'fs/promises'
import path from 'path'

export type TriageTemplate = {
  id: string
  name: string
  steps: string[]
  createdAt: string
}

function getTemplatesPath() {
  return path.join(process.cwd(), 'cases', '_shared', 'triage-templates.json')
}

export async function readTriageTemplates() {
  const templatesPath = getTemplatesPath()
  if (!existsSync(templatesPath)) {
    return [] as TriageTemplate[]
  }

  return JSON.parse(await readFile(templatesPath, 'utf8')) as TriageTemplate[]
}

export async function addTriageTemplate(name: string, steps: string[]) {
  const templatesPath = getTemplatesPath()
  await mkdir(path.dirname(templatesPath), { recursive: true })
  const templates = await readTriageTemplates()
  const template: TriageTemplate = {
    id: crypto.randomUUID(),
    name,
    steps,
    createdAt: new Date().toISOString()
  }
  templates.unshift(template)
  await writeFile(templatesPath, JSON.stringify(templates, null, 2), 'utf8')
  return template
}
