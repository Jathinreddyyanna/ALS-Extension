import { Router, Request, Response, NextFunction } from 'express'
import { validate, scanLimiter, fileLimiter } from '../middleware'
import { UrlScanSchema, FileScanSchema, ThreatEventSchema } from '../schemas'
import { scanUrl, scanFile, getDomainScore, getThreatEvents, recordThreatEvent } from '../services/scan.service'

const router = Router()

// POST /api/v1/scan/url — AI-powered URL threat analysis
router.post('/url', scanLimiter, validate(UrlScanSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    res.json(await scanUrl(req.body))
  } catch (err) { next(err) }
})

// POST /api/v1/scan/file — AI-powered file safety scan
router.post('/file', fileLimiter, validate(FileScanSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    res.json(await scanFile(req.body))
  } catch (err) { next(err) }
})

// POST /api/v1/scan/events - persist extension-side threat observations
router.post('/events', scanLimiter, validate(ThreatEventSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    await recordThreatEvent(req.body)
    res.status(201).json({ stored: true })
  } catch (err) {
    next(err)
  }
})

// GET /api/v1/scan/domain/:domain/score — domain risk score lookup
router.get('/domain/:domain/score', scanLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const score = await getDomainScore(req.params.domain)
    if (!score) return res.status(404).json({ error: 'Domain not found', domain: req.params.domain })
    res.json(score)
  } catch (err) { next(err) }
})

// GET /api/v1/scan/events — recent detection events for a domain
router.get('/events', scanLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const domainParam = typeof req.query.domain === 'string' ? req.query.domain : undefined
    const limitParam = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : undefined
    const events = await getThreatEvents({
      domain: domainParam,
      limit: limitParam,
    })
    res.json(events)
  } catch (err) {
    next(err)
  }
})

export default router
