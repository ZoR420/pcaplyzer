import { NextResponse } from 'next/server'
import { execFile } from 'child_process'
import { promisify } from 'util'
import fs from 'fs'
import path from 'path'

const execFileAsync = promisify(execFile)

async function getDependencyWarnings() {
  try {
    const { stdout } = await execFileAsync('node', ['scripts/check-deps.js'], { cwd: process.cwd() })
    const results = JSON.parse(stdout) as Array<{ name: string; found: boolean }>
    return results.filter((item) => !item.found).map((item) => `${item.name} not detected`)
  } catch {
    return ['dependency check unavailable']
  }
}

export async function GET() {
  const warnings: string[] = []
  warnings.push(...await getDependencyWarnings())

  const uploadsDir = path.join(process.cwd(), 'uploads')
  try {
    await fs.promises.mkdir(uploadsDir, { recursive: true })
    await fs.promises.access(uploadsDir, fs.constants.W_OK)
  } catch {
    warnings.push('Uploads directory is not writable. File uploads may fail.')
  }

  return NextResponse.json({
    ok: warnings.length === 0,
    warnings
  })
}
