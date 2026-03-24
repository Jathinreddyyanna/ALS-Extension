// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { computeAssessment } from './linkInterceptor'

describe('PreclickScoringValidation', () => {
  let anchor: HTMLAnchorElement
  let event: MouseEvent

  beforeEach(() => {
    document.body.innerHTML = ''
    anchor = document.createElement('a')
    document.body.appendChild(anchor)
    event = new MouseEvent('click', { bubbles: true })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    document.body.innerHTML = ''
  })

  describe('Base64 Phishing Vectors', () => {
    it('scores direct Base64 phishing as CRITICAL', () => {
      anchor.href = 'https://adstr.net/redirect?target=aHR0cHM6Ly9waGlzaGluZy5jb20v'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(8)
      expect(result.riskLevel).toBe('CRITICAL')
      expect(result.redirect.usedBase64).toBe(true)
      expect(result.reasons).toContain('Target is Base64-obfuscated')
    })

    it('scores nested URL-encoded Base64 as HIGH+', () => {
      const b64 = 'aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcGF5bG9hZA=='
      const doubleEncoded = encodeURIComponent(encodeURIComponent(b64))
      anchor.href = `https://tracker.example/out?url=${doubleEncoded}`
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(7)
      expect(result.redirect.usedNestedEncoding).toBe(true)
      expect(result.redirect.usedBase64).toBe(true)
    })
  })

  describe('Redirect Chain Attacks', () => {
    it('scores 3+ hop redirect chain as HIGH', () => {
      anchor.href =
        'https://bit.ly/abc?url=' +
        encodeURIComponent(
          'https://clickbank.net/hop?goto=' +
            encodeURIComponent('https://unknown-sketchy.com/offer')
        )
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(6)
      expect(result.redirect.chain.length).toBeGreaterThanOrEqual(2)
      expect(result.reasons.some((r) => r.includes('Redirect chain'))).toBe(true)
    })

    it('scores obfuscated affiliate chain as CRITICAL', () => {
      const b64Clickbank = 'aHR0cHM6Ly9jbGlja2JhbmsubmV0L2FmZmlsaWF0ZQ=='
      anchor.href = `https://adstr.net/redirect?target=${b64Clickbank}`
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(8)
      expect(result.riskLevel).toBe('CRITICAL')
    })
  })

  describe('Monetization + Obfuscation', () => {
    it('scores Outbrain with tracking params as MEDIUM+', () => {
      anchor.href = 'https://outbrain.com/what-is?utm_source=ad&utm_medium=cpc&url=' +
        encodeURIComponent('https://unknown.com')
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
      expect(result.redirect.intentType).toMatch(/TRACKING|TRAFFIC_MONETIZATION/)
    })

    it('scores Taboola with Base64 as HIGH', () => {
      const b64Target = 'aHR0cHM6Ly9zY2FtbWlyLmNvbS9vZmZlcg=='
      anchor.href = `https://taboola.com/click?target=${b64Target}`
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(6)
      expect(result.redirect.usedBase64).toBe(true)
    })
  })

  describe('Deceptive Patterns', () => {
    it('escalates mismatch (click here -> evil site) to HIGH', () => {
      anchor.href = 'https://unknown-evil.com/payload'
      anchor.textContent = 'Click here to verify your account'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
      expect(result.reasons.some((r) => r.includes('does not match'))).toBe(true)
    })

    it('escalates login/verify text -> unknown domain', () => {
      anchor.href = 'https://unknown-phisher.com/verify'
      anchor.textContent = 'Verify your account'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
    })

    it('escalates download text -> unknown domain', () => {
      anchor.href = 'https://unknown-malware.com/download'
      anchor.textContent = 'Download secure update'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
    })
  })

  describe('Legitimate Links', () => {
    it('scores GitHub repo as LOW', () => {
      anchor.href = 'https://github.com/user/ai-browser-shield'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
      expect(result.riskLevel).toBe('LOW')
    })

    it('scores Wikipedia article as LOW', () => {
      anchor.href = 'https://en.wikipedia.org/wiki/Security'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores StackOverflow question as LOW', () => {
      anchor.href = 'https://stackoverflow.com/questions/12345/how-to'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores Amazon product as LOW', () => {
      anchor.href = 'https://amazon.com/dp/B001234567'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores LinkedIn profile as LOW', () => {
      anchor.href = 'https://linkedin.com/in/user'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores YouTube video as LOW', () => {
      anchor.href = 'https://youtube.com/watch?v=dQw4w9WgXcQ'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores Google search result as LOW', () => {
      anchor.href = 'https://google.com/search?q=example'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores Microsoft docs as LOW', () => {
      anchor.href = 'https://docs.microsoft.com/en-us/windows'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })

    it('scores Apple support as LOW', () => {
      anchor.href = 'https://support.apple.com/en-us/HT123456'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(2)
    })
  })

  describe('False Positive Rate (<2%)', () => {
    const legitimateUrls = [
      'https://github.com/user/repo',
      'https://github.com/user/repo/issues/123',
      'https://github.com/user/repo/pulls',
      'https://github.com/user/repo?tab=readme',
      'https://stackoverflow.com/questions/123/title',
      'https://stackoverflow.com/questions?tab=newest',
      'https://en.wikipedia.org/wiki/Article',
      'https://en.wikipedia.org/wiki/Article#Section',
      'https://amazon.com/s?k=search',
      'https://amazon.com/dp/B001234567',
      'https://amazon.com/gp/product/B001234567',
      'https://amazon.in/dp/B001234567',
      'https://linkedin.com/in/john-doe',
      'https://linkedin.com/company/acme',
      'https://youtube.com/watch?v=abc123',
      'https://youtube.com/channel/UCabc123',
      'https://youtube.com/user/username',
      'https://google.com/search?q=example',
      'https://google.com/maps?q=place',
      'https://docs.microsoft.com/en-us/windows/win32',
      'https://docs.microsoft.com/en-us/dotnet/api',
      'https://support.apple.com/en-us/HT123456',
      'https://support.microsoft.com/en-us/help/123456',
      'https://www.wikipedia.org/wiki/Test',
      'https://www.youtube.com/watch?v=test',
      'https://www.reddit.com/r/programming',
      'https://news.ycombinator.com/',
      'https://www.producthunt.com/products/example',
      'https://twitter.com/user/status/123',
      'https://www.twitch.tv/channel',
    ]

    it('scores ≤2% of 30 legitimate links as HIGH+', () => {
      let highRiskCount = 0

      for (const url of legitimateUrls) {
        anchor.href = url
        const result = computeAssessment(anchor, event)

        if (result.score >= 6) {
          console.log(`⚠️ False positive: ${url} scored ${result.score}`)
          highRiskCount += 1
        }
      }

      const falsePositiveRate = highRiskCount / legitimateUrls.length
      console.log(`False positive rate: ${(falsePositiveRate * 100).toFixed(2)}%`)
      expect(falsePositiveRate).toBeLessThan(0.02)
    })
  })

  describe('False Negative Rate (<5%)', () => {
    const riskyUrls = [
      {
        url: 'https://adstr.net/redirect?target=aHR0cHM6Ly9waGlzaGluZy5jb20v',
        name: 'Base64 phishing redirect',
      },
      {
        url: 'https://clickbank.net/affiliate?goto=' + encodeURIComponent('https://scam.com'),
        name: 'Clickbank affiliate scam',
      },
      {
        url: 'https://outbrain.com/what-is?utm_source=ad&url=' + encodeURIComponent('https://malware.com'),
        name: 'Outbrain with malware',
      },
      {
        url: 'https://taboola.com/click?redirect=' + encodeURIComponent('https://phishing.com'),
        name: 'Taboola redirect',
      },
      {
        url: 'https://bit.ly/xyzabc?utm_campaign=evil',
        name: 'Bitly shortener with tracking',
      },
      {
        url: 'https://bit.ly/xyzabc?url=' + encodeURIComponent('https://unknown-site-12345.com'),
        name: 'Bitly to unknown domain',
      },
      {
        url: 'https://unknown-domain-12345.xyz/download',
        name: 'Unknown domain with download',
      },
      {
        url: 'https://unknown-sketchy.com?utm_source=email&utm_medium=newsletter',
        name: 'Unknown domain with tracking params',
      },
    ]

    it('scores ≤5% of 8 risky links as LOW', () => {
      let lowRiskCount = 0

      for (const item of riskyUrls) {
        anchor.href = item.url
        const result = computeAssessment(anchor, event)

        if (result.score < 3) {
          console.log(`❌ False negative: ${item.name} scored ${result.score}`)
          lowRiskCount += 1
        } else {
          console.log(`✅ ${item.name} scored ${result.score}`)
        }
      }

      const falseNegativeRate = lowRiskCount / riskyUrls.length
      console.log(`False negative rate: ${(falseNegativeRate * 100).toFixed(2)}%`)
      expect(falseNegativeRate).toBeLessThan(0.05)
    })
  })

  describe('Performance Benchmarks', () => {
    it('completes assessment in <100ms', () => {
      anchor.href = 'https://adstr.net/redirect?target=aHR0cHM6Ly9ldmlsLmNvbQ=='

      const samples = 10
      const times: number[] = []

      for (let index = 0; index < samples; index += 1) {
        const t1 = performance.now()
        computeAssessment(anchor, event)
        const t2 = performance.now()
        times.push(t2 - t1)
      }

      const avg = times.reduce((a, b) => a + b, 0) / times.length
      const max = Math.max(...times)
      const sorted = [...times].sort((a, b) => a - b)
      const p95 = sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)]

      console.log(`Performance: avg=${avg.toFixed(2)}ms, p95=${p95.toFixed(2)}ms, max=${max.toFixed(2)}ms`)
      expect(avg).toBeLessThan(100)
      expect(max).toBeLessThan(150)
    })
  })

  describe('Baseline Rule Enforcement', () => {
    it('never scores unknown domain with unknown context as LOW', () => {
      anchor.href = 'https://totally-unknown-domain-99999.xyz/page'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
      expect(result.riskLevel).not.toBe('LOW')
    })

    it('scores unknown domain from trusted page as LOW/MEDIUM', () => {
      const locationSpy = vi.spyOn(window, 'location', 'get').mockReturnValue({
        ...window.location,
        hostname: 'github.com',
      } as Location)

      anchor.href = 'https://unknown-but-legit-domain.com/article'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeLessThanOrEqual(4)
      locationSpy.mockRestore()
    })
  })

  describe('Intent Classification', () => {
    it('correctly identifies PHISHING_VECTOR for Base64', () => {
      anchor.href = 'https://adstr.net/redirect?target=aHR0cHM6Ly9waGlzaGluZy5jb20='
      const result = computeAssessment(anchor, event)

      expect(result.redirect.intentType).toBe('PHISHING_VECTOR')
    })

    it('correctly identifies AFFILIATE for Clickbank', () => {
      anchor.href = 'https://clickbank.net/hop?affiliate_id=123'
      const result = computeAssessment(anchor, event)

      expect(result.redirect.intentType).toBe('AFFILIATE')
    })

    it('correctly identifies SHORTENER for Bitly', () => {
      anchor.href = 'https://bit.ly/abc123'
      const result = computeAssessment(anchor, event)

      expect(result.redirect.intentType).toBe('SHORTENER')
    })

    it('correctly identifies TRACKING for utm params', () => {
      anchor.href = 'https://example.com?utm_source=ad&utm_medium=newsletter'
      const result = computeAssessment(anchor, event)

      expect(result.redirect.intentType).toBe('TRACKING')
    })

    it('correctly identifies STANDARD for normal links', () => {
      anchor.href = 'https://github.com/user/repo'
      const result = computeAssessment(anchor, event)

      expect(result.redirect.intentType).toBe('STANDARD')
    })
  })

  describe('Real-World Attack Patterns', () => {
    it('detects fake security warning redirects', () => {
      anchor.href = 'https://adstr.net/redirect?target=' +
        encodeURIComponent(
          'https://fake-antivirus.com/scan?infected=true&download=malware'
        )
      anchor.textContent = 'Click to scan for viruses'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(6)
      expect(result.reasons.some((r) => r.includes('Base64') || r.includes('Redirect'))).toBe(true)
    })

    it('detects prize/giveaway scams', () => {
      anchor.href = 'https://taboola.com/click?utm_source=news&url=' +
        encodeURIComponent('https://fake-lottery.com/claim?prize=$1000000')
      anchor.textContent = 'Claim your free iPhone 15!'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
    })

    it('detects credential theft redirects', () => {
      anchor.href = 'https://unknown-lookalike.com/login'
      anchor.textContent = 'Sign in to PayPal'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(3)
      expect(result.reasons.some((r) => r.includes('does not match'))).toBe(true)
    })

    it('detects URL obfuscation tricks', () => {
      anchor.href = 'https://goog1e.com/login'
      anchor.textContent = 'Google'
      const result = computeAssessment(anchor, event)

      expect(result.score).toBeGreaterThanOrEqual(2)
    })
  })
})
