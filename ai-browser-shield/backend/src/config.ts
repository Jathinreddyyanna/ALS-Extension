export type AiProvider = 'gemini'

export interface AiConfig {
  provider: AiProvider
  gemini: {
    apiKey: string | null
    model: string
    temperature: number
    maxOutputTokens: number
  }
}

export interface ServerConfig {
  port: number
  nodeEnv: string
  allowedOrigins: string[]
}

export interface RateLimitConfig {
  reportsPerMinute: number
  scanPerMinute: number
  fileScanPerMinute: number
  feedPerMinute: number
  healthPerMinute: number
}

function toInt(value: string | undefined, fallback: number): number {
  const n = value ? parseInt(value, 10) : NaN
  return Number.isFinite(n) && n > 0 ? n : fallback
}

export const serverConfig: ServerConfig = {
  port: toInt(process.env.PORT, 3001),
  nodeEnv: process.env.NODE_ENV || 'development',
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean),
}

export const aiConfig: AiConfig = {
  provider: 'gemini',
  gemini: {
    apiKey: process.env.GEMINI_API_KEY || null,
    model: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    temperature: 0.0,
    maxOutputTokens: 1024,
  },
}

export const rateLimitConfig: RateLimitConfig = {
  // Defaults mirror previous hard-coded values; env vars allow tuning in prod.
  reportsPerMinute: toInt(process.env.RATE_LIMIT_REPORTS_PER_MIN, 10),
  scanPerMinute: toInt(process.env.RATE_LIMIT_SCAN_PER_MIN, 30),
  fileScanPerMinute: toInt(process.env.RATE_LIMIT_FILE_PER_MIN, 20),
  feedPerMinute: toInt(process.env.RATE_LIMIT_FEED_PER_MIN, 60),
  healthPerMinute: toInt(process.env.RATE_LIMIT_HEALTH_PER_MIN, 120),
}

/**
 * CORS helper used by the Express app. In development we allow any origin
 * (including extension pages); in production we restrict to configured origins.
 */
export function isOriginAllowed(origin: string | undefined | null): boolean {
  if (!origin) return true
  if (serverConfig.nodeEnv === 'development') return true

  if (serverConfig.allowedOrigins.length === 0) return false
  return serverConfig.allowedOrigins.some(o => origin.startsWith(o))
}

