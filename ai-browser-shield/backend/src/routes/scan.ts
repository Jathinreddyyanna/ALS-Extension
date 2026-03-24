import { Router, Request, Response, NextFunction } from 'express'
import { validate, scanLimiter, fileLimiter } from '../middleware'
import { UrlScanSchema, FileScanSchema, EmailScanSchema } from '../schemas'
import { scanUrl, scanFile, scanEmail, getDomainScore } from '../services/scan.service'

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

// POST /api/v1/scan/email — Deep AI-powered phishing analysis (New Level 2)
router.post('/email', scanLimiter, validate(EmailScanSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    res.json(await scanEmail(req.body))
  } catch (err) { next(err) }
})

// GET /api/v1/scan/domain/:domain/score — domain risk score lookup
router.get('/domain/:domain/score', scanLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const score = await getDomainScore(req.params.domain)
    if (!score) return res.status(404).json({ error: 'Domain not found', domain: req.params.domain })
    res.json(score)
  } catch (err) { next(err) }
})

export default router
