import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { addTriageTemplate, readTriageTemplates } from '@/lib/templates'

export async function GET(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const templates = await readTriageTemplates()
  return NextResponse.json({ templates })
}

export async function POST(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const body = await request.json()
    const name = typeof body.name === 'string' ? body.name.trim() : ''
    const steps = Array.isArray(body.steps)
      ? body.steps.filter((item: unknown): item is string => typeof item === 'string' && item.trim().length > 0)
      : []

    if (!name || steps.length === 0) {
      return NextResponse.json({ error: 'Template name and at least one step are required' }, { status: 400 })
    }

    const template = await addTriageTemplate(name, steps)
    return NextResponse.json({ template }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Failed to save template' }, { status: 400 })
  }
}
