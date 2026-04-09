import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { generateScapSummary, readScapSummary } from '@/lib/scap'

export async function GET(
  request: Request,
  { params }: { params: { caseId: string; artifactId: string } }
) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const summary = await readScapSummary(params.caseId, params.artifactId)
  if (!summary) {
    return NextResponse.json({ error: 'SCAP summary not generated yet' }, { status: 404 })
  }

  return NextResponse.json({ summary })
}

export async function POST(
  request: Request,
  { params }: { params: { caseId: string; artifactId: string } }
) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const summary = await generateScapSummary(params.caseId, params.artifactId)
    return NextResponse.json({ summary }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to generate SCAP summary' },
      { status: 400 }
    )
  }
}
