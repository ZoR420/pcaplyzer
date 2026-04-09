import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { addCaseNote, readCaseNotes } from '@/lib/case-notes'

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  const notes = await readCaseNotes(params.caseId)
  return NextResponse.json({ notes })
}

export async function POST(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const body = await request.json()
    const content = typeof body.content === 'string' ? body.content.trim() : ''
    if (!content) {
      return NextResponse.json({ error: 'Note content is required' }, { status: 400 })
    }

    const note = await addCaseNote(params.caseId, content)
    return NextResponse.json({ note }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Failed to save note' }, { status: 400 })
  }
}
