interface GuardResult {
  ok: boolean
  status?: number
  message?: string
  headers?: Record<string, string>
}

const rateLimitStore = new Map<string, { count: number; resetAt: number }>()

function getClientIp(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for')
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }
  return headers.get('x-real-ip') || headers.get('cf-connecting-ip') || 'unknown'
}

function extractApiKey(headers: Headers): string | null {
  const direct = headers.get('x-api-key')
  if (direct) return direct

  const auth = headers.get('authorization')
  if (auth?.startsWith('Bearer ')) {
    return auth.slice(7).trim()
  }

  return null
}

export function enforceApiGuard(headers: Headers): GuardResult {
  const requireApiKey = (process.env.REQUIRE_API_KEY || 'false').toLowerCase() === 'true'
  const expectedKey = process.env.PCAPLYZER_API_KEY

  if (requireApiKey) {
    const providedKey = extractApiKey(headers)
    if (!expectedKey || !providedKey || providedKey !== expectedKey) {
      return {
        ok: false,
        status: 401,
        message: 'Unauthorized: missing or invalid API key'
      }
    }
  }

  const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60000)
  const maxRequests = Number(process.env.RATE_LIMIT_MAX || 30)
  const clientId = `${getClientIp(headers)}::${extractApiKey(headers) || 'anon'}`
  const now = Date.now()

  const entry = rateLimitStore.get(clientId)
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(clientId, { count: 1, resetAt: now + windowMs })
    return { ok: true }
  }

  if (entry.count >= maxRequests) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000)
    return {
      ok: false,
      status: 429,
      message: 'Rate limit exceeded. Please slow down and try again.',
      headers: {
        'Retry-After': String(retryAfter)
      }
    }
  }

  entry.count += 1
  rateLimitStore.set(clientId, entry)
  return { ok: true }
}
