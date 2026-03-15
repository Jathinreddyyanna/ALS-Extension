import rateLimit from 'express-rate-limit'
import { Request, Response } from 'express'
import { rateLimitConfig } from '../config'

const handler = (_req: Request, res: Response) =>
  res.status(429).json({
    type: 'https://aibrowsershield.dev/errors/rate-limit',
    title: 'Too Many Requests',
    status: 429,
    detail: 'You are sending requests too quickly. Please slow down.',
  })

const make = (max: number, windowMs = 60_000) =>
  rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, handler })

// Reports: default 10/min (prevent spam)
export const reportLimiter = make(rateLimitConfig.reportsPerMinute)

// URL/file scan: default 30/min
export const scanLimiter = make(rateLimitConfig.scanPerMinute)

// File scan: default 20/min (AI is expensive)
export const fileLimiter = make(rateLimitConfig.fileScanPerMinute)

// Community feed: default 60/min (read-heavy)
export const feedLimiter = make(rateLimitConfig.feedPerMinute)

// Health: default 120/min
export const healthLimiter = make(rateLimitConfig.healthPerMinute)
