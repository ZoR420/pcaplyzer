import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { loadCase } from '@/lib/cases'
import { readCaseNotes } from '@/lib/case-notes'
import { buildCorrelatedCaseView } from '@/lib/correlation'

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const caseRecord = await loadCase(params.caseId)
    const notes = await readCaseNotes(params.caseId)
    const correlation = await buildCorrelatedCaseView(params.caseId)

    return NextResponse.json({
      report: {
        case: caseRecord,
        notes,
        guidedTriage: correlation.guidedTriage,
        timelinePreview: correlation.timeline.slice(0, 10),
        generatedAt: new Date().toISOString()
      }
    })
  } catch {
    return NextResponse.json({ error: 'Failed to generate report' }, { status: 400 })
  }
}
