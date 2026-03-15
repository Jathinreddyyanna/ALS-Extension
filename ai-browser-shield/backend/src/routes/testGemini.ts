import { Router, type Request, type Response } from 'express'
import { scoreUrl } from '../detection/urlScorer'
import { analyzeUrl } from '../ai/client'

const router = Router()

function computeCombined(
  heuristic: number,
  aiRiskLevel: string,
  confidence: number,
  action: string,
  signals: Record<string, number>,
  dbRiskScore: number,
  dbReportCount: number
): { score: number; riskLevel: string } {
  const aiNumeric =
    aiRiskLevel === 'CRITICAL' ? 95 :
    aiRiskLevel === 'HIGH' ? 80 :
    aiRiskLevel === 'MEDIUM' ? 50 :
    15

  const conf = Math.min(1, Math.max(0, confidence ?? 0.5))
  const reportScore = Math.min(100, dbReportCount * 20 + (dbRiskScore ?? 0))

  let score = (heuristic * 0.25) + (aiNumeric * conf * 0.65) + (reportScore * 0.10)

  if (action === 'block') score += 12
  else if (action === 'warn') score += 6
  if ((signals.typosquatScore ?? 0) > 0) score += 8
  if ((signals.ipAsHostname ?? 0) > 0) score += 15
  if ((signals.suspiciousTLD ?? 0) > 0 && (signals.suspiciousKeywords ?? 0) > 0) score += 7
  if (dbReportCount >= 3) score += 10
  if (dbReportCount >= 5) score += 10

  const final = Math.min(100, Math.round(score))
  const riskLevel =
    final >= 75 ? 'CRITICAL' :
    final >= 52 ? 'HIGH' :
    final >= 30 ? 'MEDIUM' :
    'LOW'

  return { score: final, riskLevel }
}

router.post('/', async (req: Request, res: Response) => {
  const { url } = req.body || {}
  if (!url) {
    return res.status(400).json({ error: 'url required' })
  }

  try {
    const { score: hScore, signals } = scoreUrl(url)
    const ai = await analyzeUrl(url, signals as Record<string, number>, hScore)

    const dbRiskScore = 0
    const dbReportCount = 0

    const combined = computeCombined(
      hScore,
      ai.riskLevel,
      ai.confidence,
      ai.recommendedAction,
      signals as Record<string, number>,
      dbRiskScore,
      dbReportCount
    )

    const aiNumeric =
      ai.riskLevel === 'CRITICAL' ? 95 :
      ai.riskLevel === 'HIGH' ? 80 :
      ai.riskLevel === 'MEDIUM' ? 50 :
      15

    return res.json({
      url,
      heuristic: {
        score: hScore,
        signals,
      },
      ai: {
        explanation: ai.explanation,
        riskLevel: ai.riskLevel,
        recommendedAction: ai.recommendedAction,
        confidence: ai.confidence,
        keyIndicators: ai.keyIndicators,
        numericScore: aiNumeric,
      },
      combined: {
        score: combined.score,
        riskLevel: combined.riskLevel,
        formula: `(${hScore}×0.25) + (${Math.round(aiNumeric * ai.confidence * 0.65)}) + boosts`,
      },
    })
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message })
  }
})

export default router
