import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import { errorHandler } from './middleware'
import reportsRouter from './routes/reports'
import scanRouter from './routes/scan'
import healthRouter from './routes/health'
import aiRouter from './routes/ai'
import emailSecurityRouter from './routes/emailSecurity'
import downloadsRouter from './routes/downloads'

const app = express()

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet())
app.use(cors({
  origin: (origin, cb) => {
    try {
      if (!origin || process.env.NODE_ENV === 'development') return cb(null, true)
      const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean)
      if (allowed.some(o => origin.startsWith(o))) return cb(null, true)
      cb(new Error(`CORS blocked: ${origin}`))
    } catch (err) {
      console.error('[CORS] Origin check failed:', err)
      cb(new Error('CORS origin validation failed'))
    }
  },
  credentials: true,
}))

// ── Body parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: false }))
app.set('trust proxy', 1)

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/v1/reports', reportsRouter)
app.use('/api/v1/scan',    scanRouter)
app.use('/api/v1/health',  healthRouter)
app.use('/api/v1/ai',      aiRouter)
app.use('/api/v1/security', emailSecurityRouter)
app.use('/api/v1/downloads', downloadsRouter)

// ── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({
  type: 'https://aibrowsershield.dev/errors/not-found',
  title: 'Not Found',
  status: 404,
}))

// ── Global error handler ─────────────────────────────────────────────────────
app.use(errorHandler)

export default app
