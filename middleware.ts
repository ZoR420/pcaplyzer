import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  // Only handle /api/upload requests
  if (request.nextUrl.pathname === '/api/upload') {
    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new NextResponse(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      })
    }

    // Add response headers
    const response = NextResponse.next()
    response.headers.set('Access-Control-Allow-Private-Network', 'true')
    
    return response
  }

  return NextResponse.next()
}

// Configure the middleware to only run on API routes
export const config = {
  matcher: '/api/:path*',
} 