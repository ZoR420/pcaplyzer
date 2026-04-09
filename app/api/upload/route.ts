import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { sanitizeErrorMessage, storeUploadedFile } from '@/lib/upload-storage'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const maxDuration = 60

const MAX_SIZE = 100 * 1024 * 1024

export async function POST(request: Request) {
  const guard = enforceApiGuard(request.headers)
  if (!guard.ok) {
    return new NextResponse(JSON.stringify({ error: guard.message }), {
      status: guard.status || 429,
      headers: {
        'Content-Type': 'application/json',
        ...(guard.headers || {})
      }
    })
  }

  try {
    const contentType = request.headers.get('content-type')
    if (!contentType || !contentType.includes('multipart/form-data')) {
      return new NextResponse(
        JSON.stringify({ error: 'Invalid content type. Expected multipart/form-data' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      )
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null

    if (!file) {
      return new NextResponse(JSON.stringify({ error: 'No file uploaded' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    if (file.size > MAX_SIZE) {
      return new NextResponse(JSON.stringify({ error: 'File size exceeds 100MB limit' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const { artifactId } = await storeUploadedFile(file)

    return new NextResponse(
      JSON.stringify({
        success: true,
        filename: file.name,
        size: file.size,
        artifactId
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  } catch (error) {
    console.error('Upload error:', error)
    return new NextResponse(
      JSON.stringify({ error: sanitizeErrorMessage(error, 'Failed to upload file') }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    )
  }
}
