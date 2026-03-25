import { describe, it, expect } from 'vitest'
import { scoreUrl } from './urlScorer'

describe('extension urlScorer', () => {
  it('returns low risk for trusted domains', () => {
    const result = scoreUrl('https://github.com/')
    expect(result.riskLevel).toBe('LOW')
    expect(result.score).toBe(0)
  })

  it('flags suspicious phishing-style URLs', () => {
    const result = scoreUrl('https://secure-login-paypal-account-update.xyz/verify')
    expect(result.score).toBeGreaterThan(0)
    expect(['MEDIUM', 'HIGH', 'CRITICAL']).toContain(result.riskLevel)
  })

  it('returns LOW risk for invalid URLs', () => {
    const result = scoreUrl('not-a-valid-url')
    expect(result.score).toBe(0)
    expect(result.riskLevel).toBe('LOW')
  })
})


