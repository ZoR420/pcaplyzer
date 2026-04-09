import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { addSavedRule, readSavedRules } from '@/lib/rules'

export async function GET(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const rules = await readSavedRules()
  return NextResponse.json({ rules })
}

export async function POST(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const body = await request.json()
    const name = typeof body.name === 'string' ? body.name.trim() : ''
    const pattern = typeof body.pattern === 'string' ? body.pattern.trim() : ''
    const category = body.category
    const severity = body.severity
    const enabled = body.enabled !== false

    if (!name || !pattern) {
      return NextResponse.json({ error: 'Rule name and pattern are required' }, { status: 400 })
    }

    const rule = await addSavedRule({ name, pattern, category, severity, enabled })
    return NextResponse.json({ rule }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Failed to save rule' }, { status: 400 })
  }
}
