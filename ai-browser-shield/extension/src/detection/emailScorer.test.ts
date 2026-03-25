import { describe, expect, it } from 'vitest'
import { scoreEmail } from './emailScorer'

describe('scoreEmail', () => {
  it('flags internship lure content as suspicious or dangerous', () => {
    const text = [
      'Click below link to get internship of stipend 25k per month for 4 months.',
      'Registration fee required to confirm your seat.',
      'Submit OTP and verify now.',
    ].join(' ')

    const result = scoreEmail(text, 'hr@unknown-careers.xyz', false)

    expect(result.riskScore).toBeGreaterThanOrEqual(40)
    expect(['suspicious', 'dangerous']).toContain(result.riskLabel)
    expect(result.detectedSignals.length).toBeGreaterThan(0)
  })

  it('keeps benign transactional email low risk', () => {
    const text = [
      'Subject: Payment Receipt',
      'Regards, Your monthly receipt is attached.',
      'For help, visit the official website directly.',
    ].join('\n')

    const result = scoreEmail(text, 'billing@amazon.in', false)

    expect(result.riskScore).toBeLessThan(40)
    expect(result.riskLabel).toBe('safe')
  })

  it('does not flag normal internship announcement by keyword alone', () => {
    const text = [
      'Subject: Summer Internship Program 2026',
      'We are happy to announce internship openings for engineering students.',
      'Please apply on our official careers portal.',
      'Regards, Campus Hiring Team',
    ].join('\n')

    const result = scoreEmail(text, 'careers@microsoft.com', false)

    expect(result.riskScore).toBeLessThan(40)
    expect(result.riskLabel).toBe('safe')
  })

  it('keeps scoring stable for very long email bodies', () => {
    const longBody = `${'Weekly update from team. '.repeat(3000)} internship details are attached.`

    const result = scoreEmail(longBody, 'updates@github.com', false)

    expect(result.riskScore).toBeGreaterThanOrEqual(0)
    expect(result.riskScore).toBeLessThan(40)
  })
})
