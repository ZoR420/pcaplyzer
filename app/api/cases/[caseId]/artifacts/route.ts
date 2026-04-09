import { NextResponse } from 'next/server'
import { addArtifactToCase, getAllowedCaseExtensions, getCaseArtifactStats } from '@/lib/cases'
import { enforceApiGuard } from '@/lib/api-guard'

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const caseRecord = await getCaseArtifactStats(params.caseId)
  return NextResponse.json({ case: caseRecord })
}

export async function POST(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const contentType = request.headers.get('content-type')
  if (!contentType || !contentType.includes('multipart/form-data')) {
    return NextResponse.json({ error: 'Invalid content type. Expected multipart/form-data' }, { status: 400 })
  }

  const formData = await request.formData()
  const file = formData.get('file')
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'No file uploaded' }, { status: 400 })
  }

  try {
    const { caseRecord, artifact } = await addArtifactToCase(params.caseId, file)
    return NextResponse.json({ case: caseRecord, artifact, allowedExtensions: getAllowedCaseExtensions() }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to add artifact to case' },
      { status: 400 }
    )
  }
}
