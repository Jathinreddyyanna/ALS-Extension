import { GoogleGenerativeAI } from '@google/generative-ai';
import { aiConfig } from '../config';

const apiKey = aiConfig.gemini.apiKey;

if (!apiKey) {
  console.warn('[Gemini] GEMINI_API_KEY is not set. AI explanations will use heuristic fallback.');
}

const genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null;

export interface ThreatExplainInput {
  url: string;
  heuristicRisk: number;
  domainReputation?: {
    riskScore: number;
    reportCount: number;
  };
  signals?: Record<string, any>;
  popupRedirect?: Record<string, any>;
}

export interface ThreatExplainResult {
  explanation: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  recommendedAction: 'allow' | 'warn' | 'block';
  confidence: number;
  keyIndicators: string[];
}

function extractJsonPayload(text: string): string {
  const trimmed = text.trim()
  if (!trimmed) return '{}'

  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)
  if (fenced?.[1]) return fenced[1].trim()

  const firstBrace = trimmed.indexOf('{')
  const lastBrace = trimmed.lastIndexOf('}')
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    return trimmed.slice(firstBrace, lastBrace + 1)
  }

  return trimmed
}

export async function explainThreatWithGemini(
  input: ThreatExplainInput
): Promise<ThreatExplainResult> {
  if (!genAI) {
    const riskLevel =
      input.heuristicRisk >= 80 ? 'HIGH' : input.heuristicRisk >= 50 ? 'MEDIUM' : 'LOW';

    return {
      explanation:
        riskLevel === 'HIGH'
          ? 'We detected strong indicators that this website or action may be unsafe. Proceed only if you are absolutely sure you trust it.'
          : riskLevel === 'MEDIUM'
          ? 'We detected some unusual patterns. Proceed with caution and avoid entering sensitive information.'
          : 'No strong suspicious patterns detected. Still, be cautious when entering personal or financial information.',
      riskLevel,
      recommendedAction:
        riskLevel === 'HIGH' ? 'block' : riskLevel === 'MEDIUM' ? 'warn' : 'allow',
      confidence: 0.4,
      keyIndicators: ['Heuristic-only analysis (no AI configured)'],
    };
  }

  const model = genAI.getGenerativeModel({ model: aiConfig.gemini.model });

  console.log('[Gemini] Calling model', aiConfig.gemini.model, 'for URL:', input.url);

  const prompt = `
You are a strict web security assistant. Your job is to protect non-technical users from phishing, scams, and malware.

You are given:
- A URL string.
- Optional heuristic scores.
- Optional domain reputation (e.g., report counts).
- Optional popup/redirect behavior.

You MUST:
- Analyze the URL structure itself (domain, path, parameters, keywords).
- Consider common phishing patterns, brand impersonation, credential pages, suspicious hosting.
- Treat any clear sign of phishing or malware as HIGH risk, even if heuristics are missing or low.
- Be conservative: when in doubt, lean towards warning/blocking rather than allowing.

Never mark a clearly malicious or known phishing site as LOW risk.

INPUT (JSON):
${JSON.stringify(input, null, 2)}

Return STRICT JSON only with this schema (no extra text):

{
  "explanation": string,
  "riskLevel": "LOW" | "MEDIUM" | "HIGH",
  "recommendedAction": "allow" | "warn" | "block",
  "confidence": number,
  "keyIndicators": string[]
}
`;

  const result = await model.generateContent(prompt);
  const text = result.response.text() || '{}';
  const jsonText = extractJsonPayload(text)

  try {
    const parsed = JSON.parse(jsonText);

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' =
      parsed.riskLevel === 'HIGH' || parsed.riskLevel === 'MEDIUM'
        ? parsed.riskLevel
        : 'LOW';

    // Enforce stricter floor based on heuristics and popup/redirect behavior
    if (input.heuristicRisk >= 80) riskLevel = 'HIGH';
    else if (input.heuristicRisk >= 50 && riskLevel === 'LOW') riskLevel = 'MEDIUM';

    const popupLevel = String(input.popupRedirect?.riskLevel || '').toUpperCase();
    if ((popupLevel === 'DANGEROUS' || popupLevel === 'CRITICAL') && riskLevel === 'LOW') {
      riskLevel = 'MEDIUM';
    }

    const recommendedAction: 'allow' | 'warn' | 'block' =
      parsed.recommendedAction === 'block' || parsed.recommendedAction === 'warn'
        ? parsed.recommendedAction
        : 'allow';

    const explanation =
      typeof parsed.explanation === 'string'
        ? parsed.explanation
        : 'We analyzed this website or action and generated a risk assessment.';

    const confidence =
      typeof parsed.confidence === 'number' &&
      parsed.confidence >= 0 &&
      parsed.confidence <= 1
        ? parsed.confidence
        : 0.6;

    const keyIndicators: string[] = Array.isArray(parsed.keyIndicators)
      ? parsed.keyIndicators
      : [];

    return {
      explanation,
      riskLevel,
      recommendedAction,
      confidence,
      keyIndicators,
    };
  } catch (err) {
    console.error('[Gemini] Non-JSON or invalid response:', text);
    console.error('[Gemini] Parse error:', err);

    const riskLevel =
      input.heuristicRisk >= 80 ? 'HIGH' : input.heuristicRisk >= 50 ? 'MEDIUM' : 'LOW';

    return {
      explanation:
        'We detected unusual patterns, but the AI response could not be fully parsed. Proceed with caution.',
      riskLevel,
      recommendedAction:
        riskLevel === 'HIGH' ? 'block' : riskLevel === 'MEDIUM' ? 'warn' : 'allow',
      confidence: 0.5,
      keyIndicators: ['Heuristic risk with partial AI analysis'],
    };
  }
}
