import { Request, Response, NextFunction } from 'express'
import crypto from 'crypto'

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction) {
  console.error('[Error]', err.stack || err.message)

  // Handle known error types
  if (err.name === 'PrismaClientKnownRequestError') {
    return res.status(409).json({
      type: 'https://aibrowsershield.dev/errors/conflict',
      title: 'Database Conflict',
      status: 409,
      detail: 'A database constraint was violated.',
    })
  }

  if (err.name === 'PrismaClientValidationError') {
    return res.status(400).json({
      type: 'https://aibrowsershield.dev/errors/bad-request',
      title: 'Bad Request',
      status: 400,
      detail: 'Invalid data provided to database.',
    })
  }

  res.status(500).json({
    type: 'https://aibrowsershield.dev/errors/internal',
    title: 'Internal Server Error',
    status: 500,
    detail: process.env.NODE_ENV === 'development'
      ? err.message
      : 'An unexpected error occurred. Please try again.',
  })
}

export function hashIp(ip: string): string {
  return crypto
    .createHash('sha256')
    .update(ip + (process.env.IP_HASH_SALT || 'abs-salt-hackathon-2025'))
    .digest('hex')
    .slice(0, 16)
}
