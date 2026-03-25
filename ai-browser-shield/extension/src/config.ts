const DEFAULT_API_BASE_URL = 'http://localhost:3001/api/v1'
const DEFAULT_API_KEY =
  (typeof import.meta !== 'undefined' && (import.meta as ImportMeta).env?.VITE_API_KEY) ||
  ''
const DEFAULT_REQUEST_SIGNATURE_SECRET =
  (typeof import.meta !== 'undefined' && (import.meta as ImportMeta).env?.VITE_REQUEST_SIGNATURE_SECRET) ||
  ''

type LegacyKey = 'apiBaseUrl' | 'backendUrl' | 'fastApiBaseUrl'

/**
 * Returns true when the URL points to a loopback development server.
 */
function isLocalDevelopmentUrl(value: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(value)
}

/**
 * Normalize a base URL and ensure it includes the `/api/v1` suffix.
 * Returns `null` when there is no usable input.
 */
export function normalizeApiBaseUrl(input: string | null | undefined): string | null {
  const raw = (input || '').trim()
  if (!raw) return null

  let base = raw.replace(/\/+$/, '')
  if (!/\/api\/v1$/i.test(base)) base = `${base}/api/v1`
  if (!isLocalDevelopmentUrl(base) && !/^https:\/\//i.test(base)) return null
  return base
}

async function getRawStoredApiBaseUrl(): Promise<{ value: string | null; key: LegacyKey | null }> {
  return new Promise(resolve => {
    chrome.storage.sync.get(['apiBaseUrl', 'backendUrl', 'fastApiBaseUrl'], (r) => {
      const apiBaseUrl = (r.apiBaseUrl || '').trim()
      if (apiBaseUrl) {
        resolve({ value: apiBaseUrl, key: 'apiBaseUrl' })
        return
      }

      const backendUrl = (r.backendUrl || '').trim()
      if (backendUrl) {
        resolve({ value: backendUrl, key: 'backendUrl' })
        return
      }

      const fastApiBaseUrl = (r.fastApiBaseUrl || '').trim()
      if (fastApiBaseUrl) {
        resolve({ value: fastApiBaseUrl, key: 'fastApiBaseUrl' })
        return
      }

      resolve({ value: null, key: null })
    })
  })
}

/**
 * Returns the configured API base URL (normalized) or `null` if the
 * user has not configured anything. This is used by background logic
 * that should simply disable backend calls when no base URL is set.
 *
 * Performs a non-destructive migration from any legacy keys to
 * `apiBaseUrl` the first time it is called.
 */
export async function getConfiguredApiBaseUrl(): Promise<string | null> {
  const { value, key } = await getRawStoredApiBaseUrl()
  const normalized = normalizeApiBaseUrl(value)

  if (normalized && key !== 'apiBaseUrl') {
    // Write the canonical key but do not remove legacy keys or any
    // local history; this keeps the migration non-destructive.
    chrome.storage.sync.set({ apiBaseUrl: value! })
  }

  return normalized
}

/**
 * Returns the effective API base URL for the extension UI / API client.
 * If the user has never configured a backend, falls back to localhost.
 */
export async function getEffectiveApiBaseUrl(): Promise<string> {
  const configured = await getConfiguredApiBaseUrl()
  return configured || DEFAULT_API_BASE_URL
}

export async function getEffectiveApiKey(): Promise<string> {
  return new Promise(resolve => {
    chrome.storage.sync.get(['apiKey'], (result) => {
      const configured = typeof result.apiKey === 'string' ? result.apiKey.trim() : ''
      resolve(configured || DEFAULT_API_KEY)
    })
  })
}

export async function getEffectiveGeminiKey(): Promise<string | null> {
  return new Promise(resolve => {
    chrome.storage.sync.get(['geminiApiKey'], (result) => {
      const key = typeof result.geminiApiKey === 'string' ? result.geminiApiKey.trim() : ''
      resolve(key || null)
    })
  })
}

/**
 * Returns the shared request-signing secret when the extension is configured for signed API calls.
 */
export async function getEffectiveRequestSignatureSecret(): Promise<string | null> {
  return new Promise(resolve => {
    chrome.storage.sync.get(['requestSignatureSecret'], (result) => {
      const configured = typeof result.requestSignatureSecret === 'string'
        ? result.requestSignatureSecret.trim()
        : ''
      resolve(configured || DEFAULT_REQUEST_SIGNATURE_SECRET || null)
    })
  })
}

export { DEFAULT_API_BASE_URL, DEFAULT_API_KEY }
