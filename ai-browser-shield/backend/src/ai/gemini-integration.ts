import { GoogleGenerativeAI } from '@google/generative-ai'
import { aiConfig } from '../config'

const apiKey = aiConfig.gemini.apiKey
if (!apiKey) {
  console.warn('GEMINI_API_KEY is not set. Download AI analysis will be disabled.')
}

const genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null

export interface DownloadAnalysisInput {
  filename: string
  extension: string
  mimeType: string
}

export interface DownloadAnalysisResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  score: number
  explanation: string
  indicators: string[]
  recommendations: string[]
}

export async function analyzeDownload(
  input: DownloadAnalysisInput
): Promise<DownloadAnalysisResult> {
  if (!genAI) {
    return {
      verdict: 'SUSPICIOUS',
      confidence: 0.3,
      score: 50,
      explanation:
        'AI analysis is not configured. Treat this file with caution and only open it if you fully trust the source.',
      indicators: [],
      recommendations: [
        'Verify the source of the file',
        'Scan with antivirus before opening',
      ],
    }
  }

  const model = genAI.getGenerativeModel({ model: aiConfig.gemini.model })

  const prompt = `
You are a malware analyst. Analyze this downloaded file based on its metadata.

FILE:
- Filename: ${input.filename}
- Extension: ${input.extension}
- MIME Type: ${input.mimeType}

Assess whether the file is likely SAFE, SUSPICIOUS, or MALICIOUS.

Return STRICT JSON ONLY (no extra text) with this schema:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": number (0-1),
  "score": number (0-100, higher = more risky),
  "explanation": "string (1-2 sentence explanation)",
  "indicators": ["string list of key reasons"],
  "recommendations": ["string list of user actions (e.g., don't open, scan with AV)"]
}
`

  const result = await model.generateContent(prompt)
  const text = result.response.text() || '{}'

  try {
    return JSON.parse(text) as DownloadAnalysisResult
  } catch (err) {
    console.error('[Gemini Download] Non-JSON response:', text)
    return {
      verdict: 'SUSPICIOUS',
      confidence: 0.4,
      score: 60,
      explanation:
        'We detected potential risk, but could not parse the full AI analysis. Treat this file with caution.',
      indicators: [],
      recommendations: [
        'Avoid opening this file unless absolutely necessary',
        'Scan with antivirus software',
      ],
    }
  }
}
