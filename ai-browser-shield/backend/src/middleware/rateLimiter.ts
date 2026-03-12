import rateLimit from 'express-rate-limit'
import { Request, Response } from 'express'

const handler = (_req: Request, res: Response) =>
  res.status(429).json({
    type: 'https://aibrowsershield.dev/errors/rate-limit',
    title: 'Too Many Requests',
    status: 429,
    detail: 'You are sending requests too quickly. Please slow down.',
  })

const make = (max: number, windowMs = 60_000) =>
  rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, handler })

// Reports: 10/min (prevent spam)
export const reportLimiter = make(10)

// URL/file scan: 30/min
export const scanLimiter = make(30)

// File scan: 20/min (AI is expensive)
export const fileLimiter = make(20)

// Community feed: 60/min (read-heavy)
export const feedLimiter = make(60)

// Health: 120/min
export const healthLimiter = make(120)
