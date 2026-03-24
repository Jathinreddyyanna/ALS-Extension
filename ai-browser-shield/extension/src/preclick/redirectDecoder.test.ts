// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { decodeRedirectChain } from './redirectDecoder'

describe('decodeRedirectChain', () => {
  it('decodes a Base64 target parameter into the final phishing destination', () => {
    const encoded = 'aHR0cHM6Ly9waGlzaGluZy5jb20vbG9naW4='
    const result = decodeRedirectChain(`https://adstr.net/redirect?target=${encoded}`)

    expect(result.finalUrl).toBe('https://phishing.com/login')
    expect(result.usedBase64).toBe(true)
    expect(result.intentType).toBe('PHISHING_VECTOR')
    expect(result.redirectParams).toContain('target')
  })

  it('decodes nested URL-encoded Base64 redirect parameters', () => {
    const encoded = encodeURIComponent(encodeURIComponent('aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcGF5bG9hZA=='))
    const result = decodeRedirectChain(`https://tracker.example/out?url=${encoded}`)

    expect(result.finalUrl).toBe('https://evil.example/payload')
    expect(result.usedNestedEncoding).toBe(true)
    expect(result.usedBase64).toBe(true)
  })

  it('extracts multi-hop chains and tracking parameters', () => {
    const result = decodeRedirectChain(
      'https://bit.ly/abc?utm_source=newsletter&url=https%3A%2F%2Fclickbank.net%2Fhop%3Fgoto%3Dhttps%253A%252F%252Fmerchant.example%252Foffer'
    )

    expect(result.chain.length).toBeGreaterThanOrEqual(2)
    expect(result.trackingParams).toContain('utm_source')
    expect(result.finalUrl).toContain('merchant.example/offer')
  })
})
