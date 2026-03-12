import { Router, Request, Response, NextFunction } from 'express'
import { validate, reportLimiter, feedLimiter, hashIp } from '../middleware'
import { ReportSchema } from '../schemas'
import { createReport, getRecentFeed } from '../services/report.service'

const router = Router()

// POST /api/v1/reports
router.post('/', reportLimiter, validate(ReportSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ip = (req.ip || req.socket.remoteAddress || 'unknown').replace('::ffff:', '')
    const report = await createReport(req.body, hashIp(ip), req.headers['user-agent'])
    res.status(201).json({ id: report.id, status: 'accepted', domain: report.domain, createdAt: report.createdAt })
  } catch (err) { next(err) }
})

// GET /api/v1/reports/recent
router.get('/recent', feedLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit as string) || 20)
    res.json(await getRecentFeed(limit))
  } catch (err) { next(err) }
})

export default router
