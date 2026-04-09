import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { compareCases } from '@/lib/compare'

export async function POST(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const body = await request.json()
    const leftCaseId = typeof body.leftCaseId === 'string' ? body.leftCaseId : ''
    const rightCaseId = typeof body.rightCaseId === 'string' ? body.rightCaseId : ''

    if (!leftCaseId || !rightCaseId) {
      return NextResponse.json({ error: 'Two case IDs are required' }, { status: 400 })
    }

    const comparison = await compareCases(leftCaseId, rightCaseId)
    return NextResponse.json({ comparison })
  } catch {
    return NextResponse.json({ error: 'Failed to compare cases' }, { status: 400 })
  }
}
