/**
 * Computes a SHA-256 hex digest for the provided value.
 */
export async function sha256Hex(value: string): Promise<string> {
  const buffer = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Converts an absolute URL into a privacy-safe token for local persistence.
 */
export async function toHashedUrl(rawUrl: string): Promise<string> {
  return `hash:${await sha256Hex(rawUrl)}`
}

/**
 * Builds the request-signing payload expected by the backend middleware.
 */
export function createRequestSigningPayload(
  method: string,
  path: string,
  timestamp: number,
  rawBody: string
): string {
  return `${method}\n${path}\n${timestamp}\n${rawBody}`
}

/**
 * Generates the HMAC signature used for backend request authentication.
 */
export async function signRequestPayload(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}
