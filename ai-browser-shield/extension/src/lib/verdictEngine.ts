import { normalizeHostname } from './homographDefense'

export type RiskLevel = 0 | 1 | 2 | 3

export interface VerdictSignal {
  level?: RiskLevel | null
  score?: number | null
  hostname?: string | null
  source?: string
}

export interface VerdictComputationInput {
  preclick?: VerdictSignal | null
  backend?: VerdictSignal | null
  runtime?: VerdictSignal | null
}

export interface VerdictComputationResult {
  level: RiskLevel
  score: number
  reasons: string[]
  homographDetected: boolean
}

/**
 * Converts the extension's string-based risk labels into a deterministic numeric scale.
 *
 * @param riskLevel Extension risk label.
 * @returns Numeric risk level from 0 to 3.
 */
export function toNumericRiskLevel(riskLevel?: string | null): RiskLevel {
  switch ((riskLevel ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 3
    case 'HIGH':
      return 2
    case 'MEDIUM':
      return 1
    default:
      return 0
  }
}

/**
 * Converts a numeric verdict level back into the extension's public string label.
 *
 * @param level Numeric risk level.
 * @returns String risk level used by popup and background state.
 */
export function toNamedRiskLevel(level: RiskLevel): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (level >= 3) return 'CRITICAL'
  if (level === 2) return 'HIGH'
  if (level === 1) return 'MEDIUM'
  return 'LOW'
}

/**
 * Computes one authoritative verdict by only escalating signals across subsystems.
 * The result is deterministic and capped to prevent runaway normalization loops.
 *
 * @param input Risk inputs from pre-click, backend, and runtime layers.
 * @returns Canonical verdict plus transparent escalation reasons.
 */
export function computeFinalVerdict(input: VerdictComputationInput): VerdictComputationResult {
  let iterations = 0
  let strongestLevel: RiskLevel = 0
  let strongestScore = 0
  let homographDetected = false
  const reasons = new Set<string>()
  const candidates = [input.preclick, input.backend, input.runtime]

  for (const candidate of candidates) {
    iterations += 1
    if (iterations > 10) break
    if (!candidate) continue

    const level = candidate.level ?? 0
    const baseScore = Math.max(0, Math.min(100, Number(candidate.score ?? level * 30)))
    let adjustedScore = baseScore

    if (candidate.hostname) {
      const homograph = normalizeHostname(candidate.hostname)
      if (homograph.changed) {
        adjustedScore = Math.min(100, adjustedScore + homograph.riskAdded)
        homographDetected = true
        reasons.add(`Hostname normalized from ${candidate.hostname} to ${homograph.normalized}`)
      }
    }

    const adjustedLevel = Math.max(level, toNumericRiskLevel(adjustedScore >= 75 ? 'CRITICAL' : adjustedScore >= 55 ? 'HIGH' : adjustedScore >= 35 ? 'MEDIUM' : 'LOW'))
    strongestLevel = Math.max(strongestLevel, adjustedLevel) as RiskLevel
    strongestScore = Math.max(strongestScore, adjustedScore)

    if (candidate.source) {
      reasons.add(`Escalated by ${candidate.source}`)
    }
  }

  return {
    level: strongestLevel,
    score: strongestScore,
    reasons: Array.from(reasons),
    homographDetected,
  }
}
