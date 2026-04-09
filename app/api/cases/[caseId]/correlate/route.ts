import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { buildCorrelatedCaseView } from '@/lib/correlation'

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const correlation = await buildCorrelatedCaseView(params.caseId)
    return NextResponse.json({ correlation })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to build case correlation' },
      { status: 400 }
    )
  }
}
