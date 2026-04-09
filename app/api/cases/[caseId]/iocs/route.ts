import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { buildFindings } from '@/lib/findings'

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const findings = await buildFindings(params.caseId)
    const text = findings.iocs.join('\n')
    return new Response(text, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="${params.caseId}-iocs.txt"`
      }
    })
  } catch {
    return NextResponse.json({ error: 'Failed to export IOCs' }, { status: 400 })
  }
}
