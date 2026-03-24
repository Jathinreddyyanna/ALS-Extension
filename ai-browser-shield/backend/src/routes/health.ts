import { Router, Request, Response } from 'express'
import { prisma } from '../db/client'
import { getRedis } from '../services/cache.service'

const router = Router()
const isNoDb = () => process.env.NO_DB === 'true'

router.get('/', async (_req: Request, res: Response) => {
  const checks = { database: 'unknown', redis: 'unknown', ai: 'unknown' }

  if (isNoDb()) {
    checks.database = 'disabled'
  } else {
    await prisma.$queryRaw`SELECT 1`.then(() => { checks.database = 'connected' }).catch(() => { checks.database = 'error' })
  }
  await getRedis().ping().then(() => { checks.redis = 'connected' }).catch(() => { checks.redis = 'error' })
  checks.ai = process.env.GEMINI_API_KEY ? 'configured' : 'missing_key'

  const healthy = checks.database === 'connected' || checks.database === 'disabled'
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'degraded',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    services: checks,
  })
})

export default router
