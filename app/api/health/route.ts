import { NextResponse } from 'next/server'
import { exec } from 'child_process'
import { promisify } from 'util'
import fs from 'fs'
import path from 'path'

const execAsync = promisify(exec)

async function checkCommand(command: string) {
  try {
    await execAsync(command)
    return true
  } catch {
    return false
  }
}

export async function GET() {
  const warnings: string[] = []

  const tsharkAvailable = await checkCommand('tshark --version')
  if (!tsharkAvailable) {
    warnings.push('tshark not found. Install Wireshark/tshark to enable analysis.')
  }

  const pythonAvailable = await checkCommand('python3 --version') || await checkCommand('python --version')
  if (!pythonAvailable) {
    warnings.push('Python not found. Install Python 3 to enable chat analysis.')
  }

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
