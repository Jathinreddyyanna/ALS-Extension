// Direct Gemini API call from Chrome extension background service worker
// No backend server needed for AI — API key stored in chrome.storage.sync

const GEMINI_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent'

export async function getGeminiApiKey(): Promise<string | null> {
  return new Promise(resolve => {
    chrome.storage.sync.get('geminiApiKey', (r) => resolve(r.geminiApiKey || null))
  })
}

export interface GeminiUrlAnalysis {
  explanation: string
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  threats: string[]
  confidence: number
}

export async function analyzeUrlWithGemini(
  url: string,
  score: number,
  riskLevel: string,
  indicators: string[]
): Promise<GeminiUrlAnalysis | null> {
  const apiKey = await getGeminiApiKey()
  if (!apiKey) return null

  let hostname = url
  try { hostname = new URL(url).hostname } catch {}

  const indicatorText = indicators.length > 0
    ? `Detected red flags: ${indicators.join(', ')}`
    : 'No specific red flags from heuristics'

  const prompt = `You are a cybersecurity AI analyzing a website for the user's browser extension.

URL: ${url}
Domain: ${hostname}
Risk Score: ${score}/100 (${riskLevel})
${indicatorText}

Respond ONLY in this exact JSON format, nothing else:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "explanation": "One clear sentence telling the user what this site is and whether it's safe. Be specific about what the site actually is (e.g. 'YouTube is Google's video platform and is completely safe'). For phishing sites, explain the specific trick being used.",
  "threats": ["list", "of", "specific", "concerns"],
  "confidence": 0.0
}

Rules:
- For well-known sites (google, youtube, amazon, etc): verdict=SAFE, explain what the site is
- For phishing: explain the brand being impersonated
- For unknown safe sites: verdict=SAFE, brief description
- Keep explanation under 25 words
- confidence: 0.0-1.0`

  try {
    const res = await fetch(`${GEMINI_ENDPOINT}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 250,
        }
      })
    })

    if (!res.ok) {
      await res.json().catch(() => ({}))
      return null
    }

    const data = await res.json()
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text
    if (!text) return null

    // Parse JSON (strip markdown fences if present)
    const clean = text.replace(/```json\n?|\n?```/g, '').trim()
    const parsed = JSON.parse(clean)

    return {
      verdict: parsed.verdict || 'SAFE',
      explanation: parsed.explanation || 'Analysis complete.',
      threats: Array.isArray(parsed.threats) ? parsed.threats : [],
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.7
    }
  } catch {
    return null
  }
}
