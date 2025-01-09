import { NextResponse } from 'next/server'
import { writeFile, mkdir } from 'fs/promises'
import { join } from 'path'
import { existsSync } from 'fs'

// Configure the API route for large file uploads
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
// Set maximum file size to 100MB
export const maxDuration = 60
// https://nextjs.org/docs/app/api-reference/file-conventions/route-segment-config
export async function POST(request: Request) {
  console.log('Upload endpoint hit')
  
  try {
    // Ensure the request is multipart/form-data
    const contentType = request.headers.get('content-type')
    if (!contentType || !contentType.includes('multipart/form-data')) {
      console.error('Invalid content type:', contentType)
      return new NextResponse(
        JSON.stringify({ error: 'Invalid content type. Expected multipart/form-data' }),
        { 
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    }

    const formData = await request.formData()
    const file = formData.get('file') as File
    console.log('Received file:', file?.name, file?.size)

    if (!file) {
      console.log('No file received')
      return new NextResponse(
        JSON.stringify({ error: 'No file uploaded' }),
        { 
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    }

    // Validate file size (100MB limit)
    const MAX_SIZE = 100 * 1024 * 1024 // 100MB
    if (file.size > MAX_SIZE) {
      console.error('File too large:', file.size)
      return new NextResponse(
        JSON.stringify({ error: 'File size exceeds 100MB limit' }),
        { 
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    }

    // Convert the file to buffer
    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)

    // Create uploads directory if it doesn't exist
    const uploadDir = join(process.cwd(), 'uploads')
    try {
      if (!existsSync(uploadDir)) {
        console.log('Creating uploads directory:', uploadDir)
        await mkdir(uploadDir, { recursive: true })
      }
    } catch (error) {
      console.error('Error creating uploads directory:', error)
      return new NextResponse(
        JSON.stringify({ error: 'Failed to create uploads directory' }),
        { 
          status: 500,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    }

    const filePath = join(uploadDir, file.name)
    console.log('Saving file to:', filePath)

    try {
      await writeFile(filePath, buffer)
      console.log('File saved successfully')
      return new NextResponse(
        JSON.stringify({ 
          success: true, 
          filename: file.name,
          size: file.size,
          path: filePath
        }),
        { 
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    } catch (error) {
      console.error('Error saving file:', error)
      return new NextResponse(
        JSON.stringify({ error: 'Error saving file' }),
        { 
          status: 500,
          headers: {
            'Content-Type': 'application/json',
          }
        }
      )
    }
  } catch (error) {
    console.error('Upload error:', error)
    return new NextResponse(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        }
      }
    )
  }
} 