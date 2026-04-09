import { NextResponse } from 'next/server'
import { createCase, listCases } from '@/lib/cases'
import { enforceApiGuard } from '@/lib/api-guard'

export async function GET(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const cases = await listCases()
  return NextResponse.json({ cases })
}

export async function POST(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const body = await request.json().catch(() => ({})) as { title?: string }
  const caseRecord = await createCase(body.title)
  return NextResponse.json({ case: caseRecord }, { status: 201 })
}
