import { NextResponse } from 'next/server'
import { existsSync } from 'fs'
import { readFile } from 'fs/promises'
import path from 'path'
import { loadCase } from '@/lib/cases'
import { enforceApiGuard } from '@/lib/api-guard'
import { readScapSummary } from '@/lib/scap'

async function loadDerivedArtifacts(caseId: string) {
  const caseRecord = await loadCase(caseId)
  const derived = await Promise.all(
    caseRecord.artifacts.map(async (artifact) => {
      if (artifact.kind === 'scap') {
        return {
          artifactId: artifact.id,
          kind: artifact.kind,
          summary: await readScapSummary(caseId, artifact.id)
        }
      }

      const legacyUploadManifest = path.join(process.cwd(), 'uploads', `${artifact.originalName}.json`)
      const manifestExists = existsSync(legacyUploadManifest)
      const manifest = manifestExists ? JSON.parse(await readFile(legacyUploadManifest, 'utf8')) : null
      return {
        artifactId: artifact.id,
        kind: artifact.kind,
        summary: manifest
      }
    })
  )

  return derived
}

export async function GET(request: Request, { params }: { params: { caseId: string } }) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return NextResponse.json({ error: guard.message }, { status: guard.status || 429, headers: guard.headers })
  }

  try {
    const caseRecord = await loadCase(params.caseId)
    const derivedArtifacts = await loadDerivedArtifacts(params.caseId)

    return NextResponse.json({
      case: caseRecord,
      derivedArtifacts,
      exportedAt: new Date().toISOString()
    })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to export case' },
      { status: 400 }
    )
  }
}
