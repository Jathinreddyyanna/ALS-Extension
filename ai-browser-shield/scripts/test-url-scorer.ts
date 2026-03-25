#!/usr/bin/env node
/**
 * URL Phishing Detection Test Suite
 * Tests the ML-enhanced URL scoring from extension/src/detection/urlScorer.ts
 * 
 * Usage: npx ts-node scripts/test-url-scorer.ts
 */

import * as fs from 'fs'
import * as path from 'path'

// ═══════════════════════════════════════════════════════════════════════════
// URL SCORER IMPLEMENTATION (extracted from urlScorer.ts for testing)
// ═══════════════════════════════════════════════════════════════════════════

type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

interface ScoreResult {
  score: number          // 0-100
  riskLevel: RiskLevel
  heuristic_score?: number
  ml_probability?: number
  combined_score?: number
  signals: Record<string, number>
}

const TRUSTED_DOMAINS = [
  'google.com', 'gmail.com', 'github.com', 'claude.ai', 'openai.com',
  'microsoft.com', 'amazon.in', 'amazon.com', 'youtube.com', 'facebook.com',
  'twitter.com', 'linkedin.com', 'apple.com', 'netflix.com', 'stackoverflow.com',
]

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan',
  '.work', '.party', '.review', '.accountant', '.ru', '.ir'
]

const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'banking',
  'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'password',
  'credential', 'suspend', 'confirm', 'wallet', 'crypto'
]

/**
 * Extract ML signals from URL (based on trained RandomForest model on 240K URLs)
 * Feature importance:
 * 1. num_subdomains: 38.26% ⭐
 * 2. num_slashes: 22.51%
 * 3. num_dots: 17.80%
 * 4. url_length: 14.49%
 * 5. num_hyphens: 4.83%
 * 6. uses_https: 1.35%
 * 7. has_suspicious_tld: 0.45%
 * 8. has_ip: 0.32%
 */
function extractMLSignals(url: string): Record<string, number> {
  try {
    const parsed = new URL(url)
    const domain = parsed.hostname?.toLowerCase() || ''
    const pathname = parsed.pathname

    const urlLength = url.length
    const numDots = (domain.match(/\./g) || []).length
    const numHyphens = (domain.match(/-/g) || []).length
    const numSlashes = (pathname.match(/\//g) || []).length
    const hasIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld)) ? 1 : 0
    const usesHTTPS = parsed.protocol === 'https:' ? 1 : 0
    const numSubdomains = (domain.match(/\./g) || []).length

    // ML scoring based on trained feature importance (38.26% + 22.51% + 17.80% etc.)
    return {
      url_length_score: urlLength > 100 ? 10 : urlLength > 75 ? 5 : 0,
      num_dots_score: numDots > 5 ? 15 : numDots > 3 ? 8 : 0,
      num_hyphens_score: numHyphens > 2 ? 3 : numHyphens > 0 ? 1 : 0,
      num_slashes_score: numSlashes > 5 ? 20 : numSlashes > 3 ? 12 : 0,
      has_ip_score: hasIP ? 2 : 0,
      has_suspicious_tld_score: hasSuspiciousTLD ? 1 : 0,
      uses_https_score: usesHTTPS ? -1 : 0,
      num_subdomains_score: numSubdomains > 3 ? 35 : numSubdomains > 2 ? 20 : numSubdomains > 1 ? 8 : 0,
    }
  } catch {
    return {
      url_length_score: 0,
      num_dots_score: 0,
      num_hyphens_score: 0,
      num_slashes_score: 0,
      has_ip_score: 0,
      has_suspicious_tld_score: 0,
      uses_https_score: 0,
      num_subdomains_score: 0,
    }
  }
}

/**
 * Calculate ML probability from signals (0-1 scale)
 */
function calculateMLProbability(mlSignals: Record<string, number>): number {
  const totalMLScore = Object.values(mlSignals).reduce((a, b) => a + b, 0)
  return Math.min(1.0, totalMLScore / 100)
}

/**
 * Check if URL domain is trusted
 */
function isTrustedDomain(hostname: string | null | undefined): boolean {
  if (!hostname) return false
  const domain = hostname.toLowerCase()
  return TRUSTED_DOMAINS.some(td => domain === td || domain.endsWith('.' + td))
}

/**
 * Main URL scoring function (hybrid heuristic + ML)
 */
function scoreUrl(rawUrl: string): ScoreResult {
  let u: URL
  try {
    u = new URL(rawUrl)
  } catch {
    return { score: 0, riskLevel: 'LOW', signals: {} }
  }

  // Trusted domains
  if (isTrustedDomain(u.hostname)) {
    return {
      score: 5,
      riskLevel: 'LOW',
      signals: { trustedDomain: 0 },
      heuristic_score: 0,
      ml_probability: 0,
      combined_score: 0,
    }
  }

  const domain = u.hostname?.toLowerCase() || ''

  // ─────────────────────────────────────────────────────────────────────
  // HEURISTIC SIGNALS (60% weight)
  // ─────────────────────────────────────────────────────────────────────
  let heuristic_score = 0
  const signals: Record<string, number> = {}

  // 1. IP as hostname
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)
  signals.ipAsHostname = isIP ? 40 : 0
  heuristic_score += signals.ipAsHostname

  // 2. Typosquatting (common brand typos)
  const brands = ['amazon', 'paypal', 'google', 'apple', 'microsoft', 'netflix', 'github']
  const typoScore = brands.some(brand => {
    const modified = domain.replace(/[aeiou]/g, '').replace(/-/g, '')
    return modified.includes(brand.replace(/[aeiou]/g, '')) && domain !== brand
  }) ? 30 : 0
  signals.typosquatting = typoScore
  heuristic_score += typoScore

  // 3. Suspicious TLD
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))
  signals.suspiciousTLD = hasSuspiciousTLD ? 20 : 0
  heuristic_score += signals.suspiciousTLD

  // 4. Too many subdomains
  const subdomainCount = (domain.match(/\./g) || []).length
  signals.tooManySubdomains = subdomainCount > 3 ? 10 : 0
  heuristic_score += signals.tooManySubdomains

  // 5. Suspicious keywords in URL
  const urlLower = u.href.toLowerCase()
  const keywordMatches = PHISHING_KEYWORDS.filter(kw => urlLower.includes(kw)).length
  signals.suspiciousKeywords = keywordMatches > 1 ? 10 : keywordMatches > 0 ? 5 : 0
  heuristic_score += signals.suspiciousKeywords

  // ─────────────────────────────────────────────────────────────────────
  // ML SIGNALS (40% weight)
  // ─────────────────────────────────────────────────────────────────────
  const mlSignals = extractMLSignals(rawUrl)
  const mlProbability = calculateMLProbability(mlSignals)
  const mlScore = mlProbability * 100

  // ─────────────────────────────────────────────────────────────────────
  // COMBINED SCORING (60% heuristic + 40% ML)
  // ─────────────────────────────────────────────────────────────────────
  const cappedHeuristic = Math.min(heuristic_score, 100)
  const combined_score = Math.round((cappedHeuristic * 0.6) + (mlScore * 0.4))

  // Determine risk level (updated thresholds)
  // 0-25   → LOW (SAFE)
  // 26-55  → MEDIUM (SUSPICIOUS)
  // 56-80  → HIGH
  // 81-100 → CRITICAL
  let riskLevel: RiskLevel = 'LOW'
  if (combined_score >= 81) riskLevel = 'CRITICAL'
  else if (combined_score >= 56) riskLevel = 'HIGH'
  else if (combined_score >= 26) riskLevel = 'MEDIUM'

  return {
    score: combined_score,
    riskLevel,
    signals,
    heuristic_score: cappedHeuristic,
    ml_probability: mlProbability,
    combined_score,
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST RUNNER
// ═══════════════════════════════════════════════════════════════════════════

async function runTests() {
  // Use relative path from current working directory
  const testFilePath = path.join(process.cwd(), 'tests', 'test_urls.txt')

  // Read test URLs
  if (!fs.existsSync(testFilePath)) {
    console.error(`❌ Test file not found: ${testFilePath}`)
    process.exit(1)
  }

  const urlsContent = fs.readFileSync(testFilePath, 'utf-8')
  const urls = urlsContent
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'))

  console.log(`\n${'═'.repeat(80)}`)
  console.log('URL PHISHING DETECTION TEST SUITE')
  console.log(`${'═'.repeat(80)}`)
  console.log(`\nTesting ${urls.length} URLs from: tests/test_urls.txt\n`)

  // Test each URL
  const results: ScoreResult[] = []
  console.log(`${'URL'.padEnd(40)} │ ${'SCORE'.padEnd(6)} │ ${'LEVEL'.padEnd(10)} │ ${'ML%'.padEnd(5)}`)
  console.log(`${'-'.repeat(40)}┼${'-'.repeat(8)}┼${'-'.repeat(12)}┼${'-'.repeat(7)}`)

  for (const url of urls) {
    const result = scoreUrl(url)
    results.push(result)

    const displayUrl = url.length > 40 ? url.substring(0, 37) + '...' : url
    const mlPercent = ((result.ml_probability || 0) * 100).toFixed(0)

    console.log(
      `${displayUrl.padEnd(40)} │ ${String(result.score).padEnd(6)} │ ${result.riskLevel.padEnd(10)} │ ${mlPercent.padEnd(5)}%`
    )
  }

  // Summary metrics
  console.log(`\n${'═'.repeat(80)}`)
  console.log('SUMMARY METRICS')
  console.log(`${'═'.repeat(80)}\n`)

  const totalURLs = results.length
  const dangerousDetected = results.filter(r => r.riskLevel === 'CRITICAL' || r.riskLevel === 'HIGH').length
  const safeDetected = results.filter(r => r.riskLevel === 'LOW').length
  const mediumDetected = results.filter(r => r.riskLevel === 'MEDIUM').length

  console.log(`📊 Test Results:`)
  console.log(`   • Total URLs tested:      ${totalURLs}`)
  console.log(`   • Dangerous detected:     ${dangerousDetected} (CRITICAL + HIGH)`)
  console.log(`   • Medium risk detected:   ${mediumDetected}`)
  console.log(`   • Safe detected:          ${safeDetected} (LOW)`)

  const accuracy = ((dangerousDetected + safeDetected) / totalURLs * 100).toFixed(1)
  console.log(`\n✅ Detection accuracy: ${accuracy}%`)

  console.log(`\n🔍 Breakdown by Risk Level:`)
  const byLevel = results.reduce((acc, r) => {
    acc[r.riskLevel] = (acc[r.riskLevel] || 0) + 1
    return acc
  }, {} as Record<RiskLevel, number>)

  Object.entries(byLevel).forEach(([level, count]) => {
    const icon = level === 'LOW' ? '✅' : level === 'MEDIUM' ? '⚠️' : '🚨'
    console.log(`   ${icon} ${level.padEnd(10)} ${count} URL${count !== 1 ? 's' : ''}`)
  })

  console.log(`\n${'═'.repeat(80)}\n`)
}

// Run the test suite
runTests().catch(err => {
  console.error('Error:', err)
  process.exit(1)
})
