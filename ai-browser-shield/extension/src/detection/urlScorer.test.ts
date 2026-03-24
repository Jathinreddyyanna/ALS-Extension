import { describe, expect, it } from 'vitest'
import { scoreUrl } from './urlScorer'

describe('scoreUrl', () => {
  it('keeps trusted domains low risk', () => {
    const result = scoreUrl('https://google.com/search?q=security')

    expect(result.score).toBeGreaterThanOrEqual(0)
    expect(result.score).toBeLessThan(40)
    expect(result.riskLevel).toBe('LOW')
  })

  it('flags piracy-style domains as suspicious or worse', () => {
    const result = scoreUrl('https://movierulz.top/watch-online-free-download')

    expect(result.score).toBeGreaterThanOrEqual(40)
    expect(['MEDIUM', 'HIGH', 'CRITICAL']).toContain(result.riskLevel)
    expect(result.signals.piracyRisk || 0).toBeGreaterThan(0)
  })

  it('is deterministic and independent from email pipeline calls', () => {
    const first = scoreUrl('https://example-security-check.com/account/verify')
    const second = scoreUrl('https://example-security-check.com/account/verify')

    expect(second.score).toBe(first.score)
    expect(second.riskLevel).toBe(first.riskLevel)
  })
})
