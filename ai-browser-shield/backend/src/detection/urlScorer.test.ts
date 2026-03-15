import { describe, it, expect } from 'vitest'
import { scoreUrl } from './urlScorer'

describe('backend urlScorer', () => {
  it('returns low score for clearly trusted domains', () => {
    const result = scoreUrl('https://github.com/')
    expect(result.score).toBe(0)
  })

  it('returns higher score for obvious phishing-style URLs', () => {
    const result = scoreUrl('https://paypa1-security-login.xyz/verify-account')
    expect(result.score).toBeGreaterThan(0)
    expect(result.signals.suspiciousTLD).toBeGreaterThanOrEqual(0)
  })

  it('returns zero score for invalid URLs', () => {
    const result = scoreUrl('not-a-valid-url')
    expect(result.score).toBe(0)
  })
})

