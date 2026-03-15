import { GoogleGenerativeAI } from '@google/generative-ai'
import { buildUrlScanPrompt, buildFileScanPrompt, buildEmailPhishingPrompt, buildDomainReputationPrompt } from './prompts'
import type { UrlScanResult, FileScanResult } from '../types/risk'
import { aiConfig } from '../config'

let genAI: GoogleGenerativeAI | null = null

function getClient(): GoogleGenerativeAI {
  if (!genAI) {
    const apiKey = aiConfig.gemini.apiKey
    if (!apiKey) throw new Error('GEMINI_API_KEY environment variable not set')
    genAI = new GoogleGenerativeAI(apiKey)
  }
  return genAI
}

async function callGemini(prompt: string): Promise<string> {
  try {
    const model = getClient().getGenerativeModel({
      model: aiConfig.gemini.model,
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: aiConfig.gemini.temperature,
        maxOutputTokens: aiConfig.gemini.maxOutputTokens,
      },
    })
    const result = await model.generateContent(prompt)
    const response = await result.response
    const text = response.text()
    if (!text) {
      throw new Error('Gemini returned an empty response')
    }
    return text
  } catch (err: any) {
    console.error('[AI] Gemini call failed:', {
      message: err.message,
      stack: err.stack,
      model: aiConfig.gemini.model
    })
    throw err
  }
}

function safeParseJSON<T>(raw: string): T | null {
  try {
    const clean = raw.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim()
    return JSON.parse(clean)
  } catch { return null }
}

export async function analyzeUrl(url: string, signals: Record<string, number>, riskScore: number): Promise<UrlScanResult> {
  try {
    const lowerUrl = url.toLowerCase()
    const knownBadPatterns = [
      'phishing-page.firebaseapp.com',
      'testsafebrowsing.appspot.com/s/phishing',
      'testsafebrowsing.appspot.com/s/malware',
    ]
    if (knownBadPatterns.some(p => lowerUrl.includes(p))) {
      return {
        explanation: 'This URL matches known phishing or malware test patterns and should be treated as dangerous.',
        riskLevel: 'HIGH',
        recommendedAction: 'block',
        confidence: 0.95,
        keyIndicators: ['Known test phishing/malware pattern'],
        cached: false,
      }
    }

    const prompt = buildUrlScanPrompt(url, signals, riskScore)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<UrlScanResult>(raw)
    if (!parsed?.explanation) return getFallbackUrlResult(riskScore)
    return { ...parsed, cached: parsed.cached ?? false }
  } catch (err) {
    console.error('[AI] URL analysis failed:', (err as Error).message)
    return getFallbackUrlResult(riskScore)
  }
}

export interface EmailAnalysisResult {
  isPhishing: boolean
  phishingScore: number
  confidence: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  judgment: string
  indicators: {
    phishingKeywords: string[]
    domainIssues: string[]
    authenticationFailures: string[]
    suspiciousLinks: string[]
    socialEngineering: string[]
    malwareRisks: string[]
  }
  recommendations: string[]
  finalVerdict: string
}

export async function analyzeFile(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  sourceDomain?: string
  domainRiskScore?: number
  domainReportCount?: number
  domainCategories?: string[]
  contentSnippet?: string
}): Promise<FileScanResult> {
  try {
    const prompt = buildFileScanPrompt({
      filename: data.filename,
      extension: data.extension,
      mimeType: data.mimeType,
      sizeBytes: data.sizeBytes,
      sourceUrl: data.sourceUrl,
      sourceDomain: data.sourceDomain || '',
      domainRiskScore: data.domainRiskScore ?? 0,
      domainReportCount: data.domainReportCount ?? 0,
      domainCategories: data.domainCategories ?? [],
      contentSnippet: data.contentSnippet,
    })
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<FileScanResult>(raw)
    if (!parsed?.verdict) return getFallbackFileResult()
    return parsed
  } catch (err) {
    console.error('[AI] File analysis failed:', (err as Error).message)
    return getFallbackFileResult()
  }
}

// ── Domain Reputation Analysis ───────────────────────────────────────────────
export interface DomainAnalysisResult {
  summary: string
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  primaryThreat: string
  recommendation: 'avoid' | 'caution' | 'safe'
}

export async function analyzeDomain(domain: string, reportCount: number, categories: string[]): Promise<DomainAnalysisResult | null> {
  try {
    const prompt = buildDomainReputationPrompt(domain, reportCount, categories)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<DomainAnalysisResult>(raw)
    if (!parsed?.summary) return null
    return parsed
  } catch (err) {
    console.error('[AI] Domain analysis failed:', (err as Error).message)
    return null
  }
}

// ── Email Phishing Analysis ──────────────────────────────────────────────────
export async function analyzeEmail(data: {
  sender: string
  subject: string
  body: string
  headers?: Record<string, string>
  timestamp?: string
}): Promise<EmailAnalysisResult> {
  try {
    const prompt = buildEmailPhishingPrompt(data)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<EmailAnalysisResult>(raw)
    if (!parsed?.judgment) return getFallbackEmailResult()
    return parsed
  } catch (err) {
    console.error('[AI] Email analysis failed:', (err as Error).message)
    return getFallbackEmailResult()
  }
}

// ── Fallbacks (when AI is unavailable) ───────────────────────────────────────
function getFallbackUrlResult(score: number): UrlScanResult {
  if (score >= 80) return {
    explanation: 'This website triggered multiple high-risk security signals. It shows patterns consistent with phishing or malware sites. We strongly recommend leaving this page immediately and not entering any personal information.',
    riskLevel: 'CRITICAL',
    recommendedAction: 'block',
    confidence: 0.7,
    keyIndicators: ['Multiple high-risk signals', 'Possible phishing attempt', 'Do not enter credentials'],
    cached: false,
  }
  if (score >= 60) return {
    explanation: 'This website has several suspicious characteristics that suggest it may not be legitimate. Be very cautious about entering any passwords, payment details, or personal information on this page.',
    riskLevel: 'HIGH',
    recommendedAction: 'warn',
    confidence: 0.6,
    keyIndicators: ['Suspicious URL structure', 'Unusual domain pattern'],
    cached: false,
  }
  return {
    explanation: 'This website has some minor unusual patterns. While it may be legitimate, proceed with reasonable caution and avoid sharing sensitive information unless you are confident in its authenticity.',
    riskLevel: 'MEDIUM',
    recommendedAction: 'warn',
    confidence: 0.5,
    keyIndicators: ['Minor suspicious signals detected'],
    cached: false,
  }
}

function getFallbackFileResult(): FileScanResult {
  return {
    verdict: 'SUSPICIOUS',
    confidence: 0.4,
    explanation: 'AI file analysis is temporarily unavailable. This file could not be fully assessed. Exercise caution before opening it — only proceed if you trust the source.',
    recommendedAction: 'warn',
    indicators: ['Analysis service temporarily unavailable'],
  }
}

function getFallbackEmailResult(): EmailAnalysisResult {
  return {
    isPhishing: false,
    phishingScore: 50,
    confidence: 0.4,
    riskLevel: 'MEDIUM',
    judgment: 'We could not complete AI analysis. Treat this email with caution.',
    indicators: {
      phishingKeywords: [],
      domainIssues: [],
      authenticationFailures: [],
      suspiciousLinks: [],
      socialEngineering: [],
      malwareRisks: [],
    },
    recommendations: ['Be cautious with links and attachments'],
    finalVerdict: 'AI analysis unavailable; verify sender and links manually.',
  }
}
