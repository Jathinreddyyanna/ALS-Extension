import { Router } from 'express'
import { appendFile, mkdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { z } from 'zod'
import { createRateLimiter } from '../middleware/rateLimiter'
import { hashUrlForStorage } from '../utils/crypto'

const router = Router()
const FEEDBACK_LOG_PATH = join(process.cwd(), '.runtime', 'feedback-log.jsonl')

const feedbackSchema = z.object({
  url: z.string().trim().min(1).max(2048),
  verdict: z.string().trim().min(1).max(64),
  userAction: z.enum(['allowed', 'blocked', 'reported', 'dismissed', 'continued']),
}).strip()

router.post(
  '/',
  createRateLimiter({ endpoint: 'feedback_ip', limit: 120, windowMs: 60_000 }),
  async (req, res) => {
    const parsed = feedbackSchema.safeParse(req.body)
    if (!parsed.success) {
      res.status(422).json({ success: false, error: 'validation_error' })
      return
    }

    try {
      await mkdir(dirname(FEEDBACK_LOG_PATH), { recursive: true })
      await appendFile(
        FEEDBACK_LOG_PATH,
        `${JSON.stringify({
          url: hashUrlForStorage(parsed.data.url),
          verdict: parsed.data.verdict,
          userAction: parsed.data.userAction,
          timestamp: new Date().toISOString(),
        })}\n`,
        'utf8'
      )
    } catch {
      // Anonymous feedback should never fail the user flow.
    }

    res.json({ success: true })
  }
)

export default router
