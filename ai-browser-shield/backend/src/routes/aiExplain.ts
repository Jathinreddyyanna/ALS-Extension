import { Router, Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { scanUrl } from '../services/scan.service'

const router = Router()

const ExplainSchema = z.object({
  url: z.string().url().max(2048),
  hostname: z.string().optional(),
  path: z.string().optional(),
  urlSignals: z.record(z.unknown()).optional(),
  popupRedirect: z.object({
    website: z.string().optional(),
    popupCount: z.number().optional(),
    popupExceeded: z.boolean().optional(),
    redirectCount: z.number().optional(),
    riskLevel: z.string().optional(),
    flags: z.union([z.string(), z.array(z.string())]).optional(),
    blockedEvents: z.number().optional(),
    recommendedAction: z.string().optional(),
    timestamp: z.string().optional(),
  }).optional(),
  signals: z.record(z.unknown()).optional(),
  force: z.boolean().optional(),
})

function normalizeSignals(input?: Record<string, unknown>): Record<string, number> {
  if (!input) return {}
  const normalized: Record<string, number> = {}
  for (const [key, value] of Object.entries(input)) {
    if (typeof value === 'number' && Number.isFinite(value)) {
      normalized[key] = value
      continue
    }
    if (typeof value === 'string') {
      const parsed = Number(value)
      if (Number.isFinite(parsed)) normalized[key] = parsed
      continue
    }
    if (typeof value === 'boolean') {
      normalized[key] = value ? 1 : 0
    }
  }
  return normalized
}

function popupRiskSignal(riskLevel?: string): number {
  const level = (riskLevel || '').toUpperCase()
  if (level === 'CRITICAL') return 30
  if (level === 'DANGEROUS') return 20
  if (level === 'CAUTION') return 8
  return 0
}

async function handleExplain(req: Request, res: Response, next: NextFunction) {
  const parsed = ExplainSchema.safeParse(req.body)
  if (!parsed.success) {
    const errors = parsed.error.errors.map(e => ({
      field: e.path.join('.'),
      message: e.message,
      code: e.code,
    }))
    return res.status(422).json({
      type: 'https://aibrowsershield.dev/errors/validation',
      title: 'Validation Error',
      status: 422,
      detail: `${errors.length} validation error(s) found`,
      errors,
    })
  }

  const {
    url,
    signals: rawSignals,
    urlSignals: rawUrlSignals,
    popupRedirect,
    force,
  } = parsed.data

  // Support both legacy `signals` and the current extension payload field `urlSignals`.
  const signals = {
    ...normalizeSignals(rawUrlSignals),
    ...normalizeSignals(rawSignals),
  }

  if (Object.keys(signals).length === 0) {
    console.log('[aiExplain] No signals provided for URL:', url)
  }

  const popupRisk = popupRiskSignal(popupRedirect?.riskLevel)
  if (popupRisk > 0) {
    signals.popupRedirectRisk = popupRisk
  }

  try {
    const result = await scanUrl({
      url,
      signals,
      force: force ?? true,
    })
    res.json(result)
  } catch (err) {
    next(err)
  }
}

router.post('/', handleExplain)
router.post('/explainThreat', handleExplain)

export default router
