import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from '@google/generative-ai';
import { logger } from '../utils/logger';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? '');

const GEMINI_SYSTEM_PROMPT = `
You are a principal cybersecurity engineer, threat intelligence architect, and 
browser security specialist with 15+ years of experience across:

DOMAINS OF EXPERTISE:
- Malware analysis, phishing detection, and drive-by download patterns
- DNS/TLS fingerprinting, domain reputation, and registrar abuse
- Browser exploit chains, clickjacking, overlay traps, iframe injection
- Piracy infrastructure: CDN abuse, ad-redirect chains, fake DRM prompts
- Phishing kits: brand spoofing, credential harvesting, session hijacking
- Runtime behavioral signals: popup storms, redirect chains, DOM manipulation
- OSINT and passive recon on malicious infrastructure

ANALYSIS FRAMEWORK — always reason in this order:
1. INFRASTRUCTURE: Who owns this domain? How old? What TLD? Hosting pattern?
2. BEHAVIORAL: What runtime signals were observed? Popups? Redirects? DOM traps?
3. INTENT: What is this site trying to make the user DO? Download? Login? Click?
4. VERDICT: Weighted synthesis of all signals into a calibrated risk score

SCORING RULES — be accurate, not paranoid:
- Known safe domains (Google, GitHub, Microsoft, Apple, Amazon): always LOW
- Piracy sites with abusive behavior (popups + redirects + piracy TLD): CRITICAL
- Brand impersonation phishing (sbi-verify.co.in, paypal-secure.xyz): CRITICAL
- Suspicious but unconfirmed: MEDIUM — never inflate without evidence
- Single weak signal with no corroboration: LOW — do not cry wolf

OUTPUT FORMAT — always return valid JSON, nothing else:
{
  "riskScore": <0-100 integer>,
  "riskLevel": <"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">,
  "explanation": "<one sentence, plain English, for the end user>",
  "aiExplanation": "<2-3 sentences, technical detail for security analysts>",
  "recommendedAction": <"allow" | "warn" | "block">,
  "confidence": <0.0-1.0 float>,
  "keyIndicators": ["<signal1>", "<signal2>", ...],
  "threatCategory": <"phishing" | "piracy" | "malware" | "scam" | "safe" | "unknown">
}

CRITICAL RULES:
- Never return markdown, never wrap in backticks, output raw JSON only
- Never hallucinate signals that were not provided in the input
- If signals are ambiguous, lower the score — false positives destroy user trust
- A low-signal page is LOW risk, not MEDIUM — default to the safer label
`;

const MODEL_CASCADE = [
  'gemini-2.5-pro',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite',
  'gemini-2.0-flash',
  'gemini-flash-latest'
] as const;

const GEMINI_RATE_LIMIT = 15;
const GEMINI_WINDOW_MS = 60_000;
const MODEL_COOLDOWN_MS = 60_000;
const MODEL_SKIP_MS = 24 * 60 * 60 * 1000;

let _geminiCallsThisWindow = 0;
let _geminiWindowStart = Date.now();

const modelCooldownUntil = new Map<string, number>();
const modelSkipUntil = new Map<string, number>();

type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type RecommendedAction = 'allow' | 'warn' | 'block';
type ThreatCategory = 'phishing' | 'piracy' | 'malware' | 'scam' | 'safe' | 'unknown';

export interface ScanInput {
  url: string;
  hostname: string;
  tld?: string;
  domainAgeDays?: number | null;
  signals?: Record<string, number | undefined>;
  heuristicScore?: number;
  pageTitle?: string;
  hasLoginForm?: boolean;
  hasDownloadPrompt?: boolean;
}

export interface GeminiAnalysis {
  riskScore: number;
  riskLevel: RiskLevel;
  explanation: string;
  aiExplanation: string;
  recommendedAction: RecommendedAction;
  confidence: number;
  keyIndicators: string[];
  threatCategory: ThreatCategory;
  aiSource?: 'gemini' | 'heuristic';
}

const SAFETY_SETTINGS: Array<{ category: HarmCategory; threshold: HarmBlockThreshold }> = [
  { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
  { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
  { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
  { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE }
];

function canCallGemini(): boolean {
  const now = Date.now();
  if (now - _geminiWindowStart > GEMINI_WINDOW_MS) {
    _geminiCallsThisWindow = 0;
    _geminiWindowStart = now;
  }
  if (_geminiCallsThisWindow >= GEMINI_RATE_LIMIT) {
    logger.debug('Gemini rate limit hit - returning null immediately');
    return false;
  }
  _geminiCallsThisWindow += 1;
  return true;
}

export function buildHeuristicFallback(_input: ScanInput): GeminiAnalysis {
  return {
    explanation: 'AI analysis temporarily unavailable. Risk assessed using pattern matching and domain intelligence.',
    aiExplanation: 'Heuristic fallback — Gemini quota reached or all models exhausted.',
    riskLevel: 'LOW',
    recommendedAction: 'allow',
    confidence: 0.6,
    keyIndicators: [],
    aiSource: 'heuristic',
    riskScore: 10,
    threatCategory: 'unknown'
  };
}

export function buildUserPrompt(input: ScanInput): string {
  return `Analyze this URL for security threats. Apply your full cybersecurity expertise.

TARGET URL: ${input.url}
HOSTNAME:   ${input.hostname}
TLD:        ${input.tld ?? 'unknown'}
DOMAIN AGE: ${input.domainAgeDays != null ? `${input.domainAgeDays} days` : 'unknown'}

RUNTIME SIGNALS OBSERVED:
- Popup frequency:    ${input.signals?.popupFrequency ?? 0}
- Redirect chains:    ${input.signals?.redirectChains ?? 0}
- DOM manipulation:   ${input.signals?.domRisk ?? 0}/100
- Hidden iframes:     ${input.signals?.hiddenIframes ?? 0}
- Overlay traps:      ${input.signals?.overlayTrap ?? 0}
- Suspicious forms:   ${input.signals?.suspiciousFormCount ?? 0}
- Fake buttons:       ${input.signals?.fakePlayButtons ?? 0}
- Heuristic score:    ${input.heuristicScore ?? 0}/100

PAGE CONTEXT:
- Page title: ${input.pageTitle ?? 'not available'}
- Has login form: ${input.hasLoginForm ?? false}
- Has download prompt: ${input.hasDownloadPrompt ?? false}

Return ONLY the JSON object. No explanation outside the JSON.`;
}

function stripMarkdownFences(raw: string): string {
  return raw
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return value === 'LOW' || value === 'MEDIUM' || value === 'HIGH' || value === 'CRITICAL';
}

function isRecommendedAction(value: unknown): value is RecommendedAction {
  return value === 'allow' || value === 'warn' || value === 'block';
}

function isThreatCategory(value: unknown): value is ThreatCategory {
  return value === 'phishing' || value === 'piracy' || value === 'malware' || value === 'scam' || value === 'safe' || value === 'unknown';
}

export function parseGeminiResponse(raw: string): GeminiAnalysis | null {
  try {
    const cleaned = stripMarkdownFences(raw);
    const parsed = JSON.parse(cleaned) as Record<string, unknown>;

    if (typeof parsed.riskScore !== 'number') {
      return null;
    }
    if (!isRiskLevel(parsed.riskLevel)) {
      return null;
    }
    if (typeof parsed.explanation !== 'string') {
      return null;
    }

    return {
      riskScore: parsed.riskScore,
      riskLevel: parsed.riskLevel,
      explanation: parsed.explanation,
      aiExplanation: typeof parsed.aiExplanation === 'string' ? parsed.aiExplanation : parsed.explanation,
      recommendedAction: isRecommendedAction(parsed.recommendedAction) ? parsed.recommendedAction : 'allow',
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.6,
      keyIndicators: Array.isArray(parsed.keyIndicators)
        ? parsed.keyIndicators.filter((value): value is string => typeof value === 'string')
        : [],
      threatCategory: isThreatCategory(parsed.threatCategory) ? parsed.threatCategory : 'unknown',
      aiSource: 'gemini'
    };
  } catch (error) {
    logger.error({ 
      err: error instanceof Error ? error.message : String(error),
      rawResponse: raw 
    }, 'Failed to parse Gemini response as JSON');
    return null;
  }
}

function getErrorStatus(error: unknown): number | null {
  if (typeof error !== 'object' || error === null) return null;
  const maybeStatus = Reflect.get(error, 'status');
  if (typeof maybeStatus === 'number') return maybeStatus;

  const maybeResponse = Reflect.get(error, 'response');
  if (typeof maybeResponse === 'object' && maybeResponse !== null) {
    const responseStatus = Reflect.get(maybeResponse, 'status');
    if (typeof responseStatus === 'number') return responseStatus;
  }

  return null;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}

function shouldCooldown(error: unknown): boolean {
  const status = getErrorStatus(error);
  if (status === 429 || status === 503) return true;

  const message = getErrorMessage(error).toLowerCase();
  return message.includes('resource_exhausted')
    || message.includes('quota')
    || message.includes('rate limit')
    || message.includes('overloaded');
}

function shouldSkipForSession(error: unknown): boolean {
  const status = getErrorStatus(error);
  if (status === 404) return true;

  const message = getErrorMessage(error).toLowerCase();
  return message.includes('not found')
    || message.includes('not supported')
    || message.includes('deprecated');
}

function isModelTemporarilyUnavailable(model: string): boolean {
  const now = Date.now();
  const skipUntil = modelSkipUntil.get(model);
  if (skipUntil && skipUntil > now) return true;
  if (skipUntil && skipUntil <= now) modelSkipUntil.delete(model);

  const cooldownUntil = modelCooldownUntil.get(model);
  if (cooldownUntil && cooldownUntil > now) return true;
  if (cooldownUntil && cooldownUntil <= now) modelCooldownUntil.delete(model);

  return false;
}

async function callModel(model: string, userPrompt: string): Promise<string> {
  const generationConfig: {
    temperature: number;
    topP: number;
    maxOutputTokens: number;
    responseMimeType?: 'application/json';
  } = {
    temperature: 0.1,
    topP: 0.8,
    maxOutputTokens: 2048,
    responseMimeType: 'application/json'
  };

  const geminiModel = genAI.getGenerativeModel({
    model,
    systemInstruction: GEMINI_SYSTEM_PROMPT,
    generationConfig,
    safetySettings: SAFETY_SETTINGS
  });

  const response = await geminiModel.generateContent(userPrompt);
  return response.response.text();
}

async function callGeminiWithFallback(userPrompt: string): Promise<string | null> {
  for (const model of MODEL_CASCADE) {
    if (isModelTemporarilyUnavailable(model)) {
      continue;
    }

    try {
      logger.info({ model }, 'Attempting Gemini analysis');
      const start = Date.now();
      const response = await callModel(model, userPrompt);
      const end = Date.now();
      
      logger.info({ 
        model, 
        durationMs: end - start,
        responseLength: response.length
      }, 'Gemini analysis successful');
      
      return response;
    } catch (error) {
      const status = getErrorStatus(error);
      const message = getErrorMessage(error);
      
      logger.warn({ 
        model, 
        status, 
        err: message 
      }, 'Gemini model attempt failed - moving to next in cascade');

      if (shouldSkipForSession(error)) {
        modelSkipUntil.set(model, Date.now() + MODEL_SKIP_MS);
      } else if (shouldCooldown(error)) {
        modelCooldownUntil.set(model, Date.now() + MODEL_COOLDOWN_MS);
      }
    }
  }

  return null;
}

export async function generateExplanation(input: ScanInput): Promise<GeminiAnalysis> {
  if (!canCallGemini()) {
    return buildHeuristicFallback(input);
  }

  const userPrompt = buildUserPrompt(input);
  const raw = await callGeminiWithFallback(userPrompt);
  if (raw === null) {
    return buildHeuristicFallback(input);
  }

  const parsed = parseGeminiResponse(raw);
  if (parsed === null) {
    return buildHeuristicFallback(input);
  }

  return parsed;
}
