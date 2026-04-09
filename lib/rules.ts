import { existsSync } from 'fs'
import { mkdir, readFile, writeFile } from 'fs/promises'
import path from 'path'

export type SavedDetectionRule = {
  id: string
  name: string
  pattern: string
  category: 'network' | 'file' | 'process' | 'behavior'
  severity: 'low' | 'medium' | 'high'
  enabled: boolean
  createdAt: string
}

function getRulesPath() {
  return path.join(process.cwd(), 'cases', '_shared', 'saved-rules.json')
}

export async function readSavedRules() {
  const rulesPath = getRulesPath()
  if (!existsSync(rulesPath)) {
    return [] as SavedDetectionRule[]
  }

  return JSON.parse(await readFile(rulesPath, 'utf8')) as SavedDetectionRule[]
}

export async function addSavedRule(input: Omit<SavedDetectionRule, 'id' | 'createdAt'>) {
  const rulesPath = getRulesPath()
  await mkdir(path.dirname(rulesPath), { recursive: true })
  const rules = await readSavedRules()
  const rule: SavedDetectionRule = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    ...input
  }
  rules.unshift(rule)
  await writeFile(rulesPath, JSON.stringify(rules, null, 2), 'utf8')
  return rule
}
