import { GoogleGenerativeAI } from '@google/generative-ai'
import { buildUrlScanPrompt, buildFileScanPrompt, buildEmailScanPrompt } from './prompts'

let genAI: GoogleGenerativeAI | null = null

function getClient(): GoogleGenerativeAI {
  if (!genAI) {
    const apiKey = process.env.GEMINI_API_KEY
    if (!apiKey) throw new Error('GEMINI_API_KEY environment variable not set')
    genAI = new GoogleGenerativeAI(apiKey)
  }
  return genAI
}

async function callGemini(prompt: string): Promise<string> {
  const model = getClient().getGenerativeModel({
    model: 'gemini-1.5-flash',
    generationConfig: {
      responseMimeType: 'application/json',
      temperature: 0.1,
      maxOutputTokens: 1024,
    },
  })
  const result = await model.generateContent(prompt)
  return result.response.text()
}

function safeParseJSON<T>(raw: string): T | null {
  try {
    const clean = raw.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim()
    return JSON.parse(clean)
  } catch { return null }
}

// ── URL Threat Analysis ───────────────────────────────────────────────────────
export interface UrlScanResult {
  explanation: string
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  recommendedAction: 'allow' | 'warn' | 'block'
  confidence: number
  keyIndicators: string[]
}

export async function analyzeUrl(url: string, signals: Record<string, number>, riskScore: number): Promise<UrlScanResult> {
  try {
    const prompt = buildUrlScanPrompt(url, signals, riskScore)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<UrlScanResult>(raw)
    if (!parsed?.explanation) return getFallbackUrlResult(riskScore)
    return parsed
  } catch (err) {
    console.error('[AI] URL analysis failed:', (err as Error).message)
    return getFallbackUrlResult(riskScore)
  }
}

// ── File Safety Analysis ──────────────────────────────────────────────────────
export interface FileScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  explanation: string
  recommendedAction: 'keep' | 'quarantine' | 'delete'
  indicators: string[]
}

export async function analyzeFile(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  contentSnippet?: string
}): Promise<FileScanResult> {
  try {
    const prompt = buildFileScanPrompt(data)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<FileScanResult>(raw)
    if (!parsed?.verdict) return getFallbackFileResult()
    return parsed
  } catch (err) {
    console.error('[AI] File analysis failed:', (err as Error).message)
    return getFallbackFileResult()
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
  }
  if (score >= 60) return {
    explanation: 'This website has several suspicious characteristics that suggest it may not be legitimate. Be very cautious about entering any passwords, payment details, or personal information on this page.',
    riskLevel: 'HIGH',
    recommendedAction: 'warn',
    confidence: 0.6,
    keyIndicators: ['Suspicious URL structure', 'Unusual domain pattern'],
  }
  return {
    explanation: 'This website has some minor unusual patterns. While it may be legitimate, proceed with reasonable caution and avoid sharing sensitive information unless you are confident in its authenticity.',
    riskLevel: 'MEDIUM',
    recommendedAction: 'warn',
    confidence: 0.5,
    keyIndicators: ['Minor suspicious signals detected'],
  }
}

function getFallbackFileResult(): FileScanResult {
  return {
    verdict: 'SUSPICIOUS',
    confidence: 0.4,
    explanation: 'AI file analysis is temporarily unavailable. This file could not be fully assessed. Exercise caution before opening it — only proceed if you trust the source.',
    recommendedAction: 'quarantine',
    indicators: ['Analysis service temporarily unavailable'],
  }
}

// ── Email Phishing Analysis ───────────────────────────────────────────────────
export interface EmailScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS'
  confidence: number
  explanation: string
  attackType: string
  recommendedAction: 'ignore' | 'report' | 'delete'
}

export async function analyzeEmail(data: {
  sender: string
  subject: string
  body: string
  links: string[]
  localSignals: string[]
}): Promise<EmailScanResult> {
  try {
    const prompt = buildEmailScanPrompt(data)
    const raw = await callGemini(prompt)
    const parsed = safeParseJSON<EmailScanResult>(raw)
    if (!parsed?.verdict) return getFallbackEmailResult()
    return parsed
  } catch (err) {
    console.error('[AI] Email analysis failed:', (err as Error).message)
    return getFallbackEmailResult()
  }
}

function getFallbackEmailResult(): EmailScanResult {
  return {
    verdict: 'SUSPICIOUS',
    confidence: 0.5,
    explanation: 'Deep scanning is currently unavailable. This email shows some suspicious patterns locally. Please verify the sender carefully.',
    attackType: 'Phishing Attempt',
    recommendedAction: 'report',
  }
}

