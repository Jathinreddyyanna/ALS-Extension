import { GoogleGenerativeAI } from '@google/generative-ai';
import { env } from '../config';
import { cacheKeys, cacheService } from './cache.service';
import { logger } from '../utils/logger';
import { buildEmailThreatExplanationPrompt } from '../ai/prompts';
import type { AiAssessment, AiVerdict, AnalyzeWithGeminiInput, Category, RiskLevel, UrlScanResult } from '../types/scan.types';

declare global {
  // eslint-disable-next-line no-var
  var __aiDegraded__: boolean | undefined;
}

if (typeof global.__aiDegraded__ !== 'boolean') {
  global.__aiDegraded__ = false;
}

const order: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const geminiModel = env.GEMINI_MODEL.replace(/^models\//, '').trim() || 'gemini-flash-lite-latest';
const MODEL_FALLBACK_CHAIN = Array.from(new Set([
  geminiModel,
  'gemini-flash-lite-latest',
  'gemini-2.5-flash-lite',
  'gemini-flash-latest'
]));
const URL_SYSTEM_PROMPT = `You are a cybersecurity threat analyst specializing in web-based threats.
Analyze the provided URL and signals, then respond ONLY with a valid JSON object - no markdown, no explanation, no code fences.
The JSON must match this exact schema:
{
  "riskScore": <integer 0-100>,
  "riskLevel": <"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">,
  "verdict": <"safe" | "suspicious" | "malicious">,
  "aiExplanation": <string, 1-3 sentences explaining the threat>,
  "categories": <array of strings like ["phishing","typosquatting"]>,
  "signals": {
    "domainAge": <"new"|"established"|"unknown">,
    "sslValid": <boolean>,
    "redirectChain": <boolean>,
    "suspiciousPatterns": <array of strings>
  }
}`;
const FILE_SYSTEM_PROMPT = `You are a malware analyst specializing in file-based threats.
Analyze the file metadata and behavioral signals, then respond ONLY with a valid JSON object - no markdown, no explanation, no code fences.
The JSON must match this exact schema:
{
  "riskScore": <integer 0-100>,
  "riskLevel": <"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">,
  "verdict": <"safe" | "suspicious" | "malicious" | "quarantine">,
  "aiExplanation": <string, 1-3 sentences explaining the threat>,
  "categories": <array of strings like ["malware","spyware","ransomware"]>,
  "signals": {
    "fileType": <string>,
    "suspiciousBehaviors": <array of strings>,
    "knownMalwareFamily": <string | null>
  }
}`;

const clampRiskLevel = (riskLevel: RiskLevel, minimum: RiskLevel): RiskLevel =>
  order.indexOf(riskLevel) < order.indexOf(minimum) ? minimum : riskLevel;

const numericForLevel = (riskLevel: RiskLevel): number => riskLevel === 'CRITICAL' ? 95 : riskLevel === 'HIGH' ? 80 : riskLevel === 'MEDIUM' ? 50 : 15;

const deriveFromHeuristic = (input: AnalyzeWithGeminiInput): AiAssessment => {
  const riskLevel: RiskLevel = input.heuristicScore >= 75 ? 'CRITICAL' : input.heuristicScore >= 50 ? 'HIGH' : input.heuristicScore >= 30 ? 'MEDIUM' : 'LOW';
  return {
    riskLevel,
    riskScore: input.heuristicScore,
    confidence: 0.45,
    recommendedAction: riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'block' : riskLevel === 'MEDIUM' ? 'warn' : 'allow',
    explanation: 'Heuristic analysis used while AI was unavailable.',
    keyIndicators: Object.entries(input.heuristicSignals).filter(([, value]) => value > 0).map(([key]) => key).slice(0, 5),
    category: 'unknown',
    categories: [],
    verdict: riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'malicious' : riskLevel === 'MEDIUM' ? 'suspicious' : 'safe',
    threatVector: input.fileData ? 'file' : 'url_structure',
    isFalsePositiveRisk: false,
    suggestedWhitelist: false,
    source: 'heuristic',
    aiDegraded: true,
    cached: false
  };
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const createGenAiClient = (apiKey?: string | null): GoogleGenerativeAI | null => {
  const effectiveKey = (apiKey || env.GEMINI_API_KEY || '').trim();
  return effectiveKey ? new GoogleGenerativeAI(effectiveKey) : null;
};

function parseJson<T>(raw: string): T {
  const cleaned = raw
    .trim()
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();
  return JSON.parse(cleaned) as T;
}

const normalizeCategory = (value: string | undefined): Category => {
  const normalized = String(value ?? 'unknown').trim().toLowerCase();
  if (['phishing', 'malware', 'scam', 'redirect', 'popup_abuse', 'ad_abuse', 'crypto_mining', 'data_exfil', 'clean', 'unknown', 'other'].includes(normalized)) {
    return normalized as Category;
  }
  return normalized.includes('phish')
    ? 'phishing'
    : normalized.includes('malware') || normalized.includes('spyware') || normalized.includes('ransom')
      ? 'malware'
      : normalized.includes('redirect')
        ? 'redirect'
        : normalized.includes('scam')
          ? 'scam'
          : 'other';
};

const clampRiskScore = (value: unknown): number => Math.max(0, Math.min(100, Math.round(Number(value) || 0)));

const recommendedActionFor = (riskLevel: RiskLevel, verdict?: AiVerdict): AiAssessment['recommendedAction'] => {
  if (verdict === 'quarantine') {
    return 'quarantine';
  }
  if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
    return 'block';
  }
  if (riskLevel === 'MEDIUM') {
    return 'warn';
  }
  return 'allow';
};

const verdictFromRisk = (riskLevel: RiskLevel): AiVerdict => riskLevel === 'CRITICAL' || riskLevel === 'HIGH'
  ? 'malicious'
  : riskLevel === 'MEDIUM'
    ? 'suspicious'
    : 'safe';

type GeminiUrlResponse = {
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: Extract<AiVerdict, 'safe' | 'suspicious' | 'malicious'>;
  aiExplanation: string;
  categories: string[];
  signals?: {
    domainAge?: 'new' | 'established' | 'unknown';
    sslValid?: boolean;
    redirectChain?: boolean;
    suspiciousPatterns?: string[];
  };
};

type GeminiFileResponse = {
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: AiVerdict;
  aiExplanation: string;
  categories: string[];
  signals?: {
    fileType?: string;
    suspiciousBehaviors?: string[];
    knownMalwareFamily?: string | null;
  };
};

type EmailExplanationResult = {
  explanation: string;
  attackType: string;
  recommendedAction: 'ignore' | 'report' | 'delete';
  source: 'gemini' | 'rule-based';
};

const normalizeGeminiAssessment = (content: string, input: AnalyzeWithGeminiInput): AiAssessment | null => {
  try {
    if (input.fileData) {
      const parsed = parseJson<GeminiFileResponse>(content);
      const categories = Array.isArray(parsed.categories) ? parsed.categories.map((value) => String(value)).filter(Boolean).slice(0, 5) : [];
      const suspiciousBehaviors = Array.isArray(parsed.signals?.suspiciousBehaviors)
        ? parsed.signals!.suspiciousBehaviors.map((value) => String(value)).filter(Boolean)
        : [];
      const verdict = parsed.verdict ?? verdictFromRisk(parsed.riskLevel);
      return {
        riskLevel: verdict === 'quarantine' ? 'CRITICAL' : parsed.riskLevel,
        riskScore: clampRiskScore(parsed.riskScore),
        confidence: 0.9,
        recommendedAction: recommendedActionFor(verdict === 'quarantine' ? 'CRITICAL' : parsed.riskLevel, verdict),
        explanation: String(parsed.aiExplanation ?? '').trim(),
        keyIndicators: suspiciousBehaviors.slice(0, 5),
        category: normalizeCategory(categories[0]),
        categories,
        verdict,
        threatVector: 'file',
        isFalsePositiveRisk: false,
        suggestedWhitelist: false,
        source: 'gemini',
        aiDegraded: false,
        cached: false
      };
    }

    const parsed = parseJson<GeminiUrlResponse>(content);
    const categories = Array.isArray(parsed.categories) ? parsed.categories.map((value) => String(value)).filter(Boolean).slice(0, 5) : [];
    const suspiciousPatterns = Array.isArray(parsed.signals?.suspiciousPatterns)
      ? parsed.signals!.suspiciousPatterns.map((value) => String(value)).filter(Boolean)
      : [];
    return {
      riskLevel: parsed.riskLevel,
      riskScore: clampRiskScore(parsed.riskScore),
      confidence: 0.9,
      recommendedAction: recommendedActionFor(parsed.riskLevel, parsed.verdict),
      explanation: String(parsed.aiExplanation ?? '').trim(),
      keyIndicators: suspiciousPatterns.slice(0, 5),
      category: normalizeCategory(categories[0]),
      categories,
      verdict: parsed.verdict ?? verdictFromRisk(parsed.riskLevel),
      threatVector: 'url_structure',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'gemini',
      aiDegraded: false,
      cached: false
    };
  } catch (error) {
    logger.error({ content, error, requestId: input.requestId }, 'Failed to parse Gemini response as JSON');
    return null;
  }
};

const postProcess = (assessment: AiAssessment, input: AnalyzeWithGeminiInput, isAiResult: boolean): AiAssessment => {
  const next = { ...assessment };

  if (input.fileData) {
    if (next.riskLevel === 'CRITICAL' || next.riskLevel === 'HIGH') {
      next.recommendedAction = 'quarantine';
    }
    if (next.riskLevel === 'CRITICAL') {
      next.verdict = 'quarantine';
    }
    next.riskScore = Math.max(next.riskScore, numericForLevel(next.riskLevel));
    return next;
  }

  if (!isAiResult) {
    if (input.urlType === 'localhost' || input.urlType === 'private_ip') {
      next.riskLevel = 'LOW';
      next.recommendedAction = 'allow';
      next.riskScore = 15;
    }
    if (input.domainReputation.is_whitelisted && input.heuristicScore < 40 && ['HIGH', 'CRITICAL'].includes(next.riskLevel)) {
      next.riskLevel = 'MEDIUM';
    }
    if (input.heuristicScore >= 80) {
      next.riskLevel = clampRiskLevel(next.riskLevel, 'HIGH');
    }
    if (input.heuristicScore >= 50 && next.riskLevel === 'LOW') {
      next.riskLevel = 'MEDIUM';
    }
    if (input.heuristicSignals.credentialInUrl > 0) {
      next.riskLevel = clampRiskLevel(next.riskLevel, 'HIGH');
    }
    if (input.heuristicSignals.idnHomoglyph > 0) {
      next.riskLevel = clampRiskLevel(next.riskLevel, 'HIGH');
    }
    if (input.popupRedirectData?.riskLevel === 'CRITICAL' && ['LOW', 'MEDIUM'].includes(next.riskLevel)) {
      next.riskLevel = 'HIGH';
    }
  }

  next.riskScore = Math.max(next.riskScore, numericForLevel(next.riskLevel));
  next.verdict = next.verdict ?? verdictFromRisk(next.riskLevel);
  return next;
};

const create429Fallback = async (input: AnalyzeWithGeminiInput): Promise<AiAssessment> => {
  if (input.cacheKey) {
    const cached = await cacheService.get<UrlScanResult>(input.cacheKey);
    if (cached) {
      logger.warn({ requestId: input.requestId }, 'Gemini rate limited, falling back to cache_on_429');
      return {
        riskLevel: cached.riskLevel,
        riskScore: cached.riskScore,
        confidence: cached.confidence,
        recommendedAction: cached.recommendedAction,
        explanation: cached.explanation,
        keyIndicators: cached.keyIndicators,
        category: cached.category,
        threatVector: 'domain_reputation',
        isFalsePositiveRisk: false,
        suggestedWhitelist: false,
        source: 'heuristic',
        aiDegraded: true,
        cached: true
      };
    }
  }

  if (input.domain) {
    const domainCached = await cacheService.get<{ riskScore: number; reportCount?: number; trustScore?: number }>(cacheKeys.domain(input.domain));
    if (domainCached) {
      logger.warn({ requestId: input.requestId }, 'Gemini rate limited, falling back to domain_cache_on_429');
      const riskLevel: RiskLevel = domainCached.riskScore >= 75 ? 'CRITICAL' : domainCached.riskScore >= 50 ? 'HIGH' : domainCached.riskScore >= 30 ? 'MEDIUM' : 'LOW';
      return {
        riskLevel,
        riskScore: domainCached.riskScore,
        confidence: 0.4,
        recommendedAction: riskLevel === 'HIGH' || riskLevel === 'CRITICAL' ? 'block' : riskLevel === 'MEDIUM' ? 'warn' : 'allow',
        explanation: 'Domain reputation cache was used because the AI service was rate limited.',
        keyIndicators: ['domain_cache'],
        category: 'unknown',
        threatVector: 'domain_reputation',
        isFalsePositiveRisk: false,
        suggestedWhitelist: false,
        source: 'heuristic',
        aiDegraded: true,
        cached: true
      };
    }
  }

  logger.warn({ requestId: input.requestId }, 'Gemini rate limited, falling back to heuristic_on_429');
  return deriveFromHeuristic(input);
};

const buildPrompt = (input: AnalyzeWithGeminiInput) => {
  const isFileScan = Boolean(input.fileData);
  return isFileScan
    ? `Analyze this file scan input and return only the JSON object.\n${JSON.stringify(input)}`
    : `Analyze this URL scan input and return only the JSON object.\n${JSON.stringify(input)}`;
};

const generateWithFallback = async (
  client: GoogleGenerativeAI,
  prompt: string,
  systemInstruction: string,
  requestId?: string
): Promise<{ text: string; modelUsed: string }> => {
  for (const modelName of MODEL_FALLBACK_CHAIN) {
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        const model = client.getGenerativeModel({
          model: modelName,
          systemInstruction
        });
        const result = await Promise.race([
          model.generateContent({
            contents: [{ role: 'user', parts: [{ text: prompt }] }],
            generationConfig: {
              responseMimeType: 'application/json',
              temperature: 0.1,
              maxOutputTokens: 1024
            }
          }),
          new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('gemini_timeout')), env.GEMINI_TIMEOUT_MS);
          })
        ]);
        const text = result.response.text();
        if (text && text.trim().startsWith('{')) {
          return { text, modelUsed: modelName };
        }
        break;
      } catch (error) {
        const status = typeof error === 'object' && error !== null && 'status' in error
          ? (error as { status?: number }).status ?? 0
          : 0;
        if (status === 429 || status === 503 || (error instanceof Error && error.message === 'gemini_timeout')) {
          if (attempt === 1) {
            await sleep(1500);
            continue;
          }
          break;
        }
        if (status === 400 || status === 404) {
          break;
        }
        throw error;
      }
    }
  }
  throw new Error('all_gemini_models_exhausted');
};

const generateContentOnce = async (input: AnalyzeWithGeminiInput) => {
  const isFileScan = Boolean(input.fileData);
  const client = createGenAiClient(input.userGeminiKey);
  if (!client) {
    throw new Error('gemini_not_configured');
  }
  return generateWithFallback(
    client,
    buildPrompt(input),
    isFileScan ? FILE_SYSTEM_PROMPT : URL_SYSTEM_PROMPT,
    input.requestId
  );
};

const buildRuleBasedEmailExplanation = (input: {
  phishingProbability: number;
  decision: 'SAFE' | 'WARNING' | 'BLOCK';
  topFeatures: string[];
  sender: string;
  localSignals: string[];
}): EmailExplanationResult => {
  const riskPercent = Math.round(input.phishingProbability * 100);
  const senderText = input.sender || 'this sender';
  const indicators = Array.from(new Set([...input.topFeatures, ...input.localSignals])).slice(0, 3);
  const indicatorText = indicators.length > 0 ? indicators.join(', ') : 'the overall sender and content pattern';

  if (input.decision === 'BLOCK') {
    return {
      explanation: `This email looks highly suspicious (${riskPercent}% phishing probability). The strongest warning signs came from ${indicatorText}, so you should avoid clicking links or opening attachments from ${senderText}.`,
      attackType: input.topFeatures.some((item) => /attachment|malware/i.test(item)) ? 'Malware' : 'Phishing',
      recommendedAction: 'delete',
      source: 'rule-based'
    };
  }

  if (input.decision === 'WARNING') {
    return {
      explanation: `This email shows caution-level phishing indicators (${riskPercent}% phishing probability). Review ${indicatorText} carefully before trusting ${senderText} or interacting with any links.`,
      attackType: input.topFeatures.some((item) => /brand|sender/i.test(item)) ? 'Brand Impersonation' : 'Scam',
      recommendedAction: 'report',
      source: 'rule-based'
    };
  }

  return {
    explanation: `This email appears low risk (${riskPercent}% phishing probability). No strong phishing indicators were confirmed beyond ${indicatorText}, but it is still worth verifying unexpected requests from ${senderText}.`,
    attackType: 'None',
    recommendedAction: 'ignore',
    source: 'rule-based'
  };
};

/**
 * Generate a user-facing explanation for an email phishing verdict.
 */
export const generateEmailThreatExplanation = async (input: {
  sender: string;
  subject: string;
  body: string;
  phishingProbability: number;
  decision: 'SAFE' | 'WARNING' | 'BLOCK';
  topFeatures: string[];
  localSignals: string[];
  userGeminiKey?: string;
}): Promise<EmailExplanationResult> => {
  const client = createGenAiClient(input.userGeminiKey);
  if (!client) {
    return buildRuleBasedEmailExplanation(input);
  }

  try {
    const response = await generateWithFallback(
      client,
      buildEmailThreatExplanationPrompt(input),
      'Return only valid JSON for email threat explanations.',
      undefined
    );
    const parsed = parseJson<{
      explanation?: string;
      attackType?: string;
      recommendedAction?: string;
    }>(response.text);
    if (!parsed || typeof parsed.explanation !== 'string') {
      return buildRuleBasedEmailExplanation(input);
    }

    const recommendedAction = parsed.recommendedAction === 'delete' || parsed.recommendedAction === 'report' || parsed.recommendedAction === 'ignore'
      ? parsed.recommendedAction
      : buildRuleBasedEmailExplanation(input).recommendedAction;

    return {
      explanation: parsed.explanation.trim(),
      attackType: typeof parsed.attackType === 'string' && parsed.attackType.trim() ? parsed.attackType.trim() : 'Phishing',
      recommendedAction,
      source: 'gemini'
    };
  } catch (error) {
    logger.warn({ err: error, sender: input.sender }, 'email explanation generation failed');
    return buildRuleBasedEmailExplanation(input);
  }
};

export const analyzeWithGemini = async (input: AnalyzeWithGeminiInput): Promise<AiAssessment> => {
  const client = createGenAiClient(input.userGeminiKey);
  if (!client) {
    global.__aiDegraded__ = true;
    return postProcess(deriveFromHeuristic(input), input, false);
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await generateWithFallback(
        client,
        buildPrompt(input),
        input.fileData ? FILE_SYSTEM_PROMPT : URL_SYSTEM_PROMPT,
        input.requestId
      );
      const parsed = normalizeGeminiAssessment(response.text, input);
      if (!parsed) {
        logger.warn({ requestId: input.requestId }, 'heuristic_parse_fallback');
        global.__aiDegraded__ = true;
        return postProcess(deriveFromHeuristic(input), input, false);
      }
      const processed = postProcess({ ...parsed, modelUsed: response.modelUsed }, input, true);
      global.__aiDegraded__ = false;
      logger.info({ requestId: input.requestId, modelUsed: response.modelUsed }, 'gemini success');
      return processed;
    } catch (error) {
      const status = typeof error === 'object' && error !== null && 'status' in error ? (error as { status?: number }).status : undefined;
      if (status === 429 || (error instanceof Error && error.message === 'all_gemini_models_exhausted')) {
        logger.warn({ requestId: input.requestId, model: geminiModel }, 'gemini rate limited');
        global.__aiDegraded__ = true;
        return postProcess(await create429Fallback(input), input, false);
      }
      if (attempt === 0 && !(error instanceof Error && error.message === 'gemini_timeout')) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      if (error instanceof Error && error.message === 'gemini_timeout') {
        logger.warn({ requestId: input.requestId }, 'gemini timeout');
        global.__aiDegraded__ = true;
        return postProcess(deriveFromHeuristic(input), input, false);
      }
      logger.warn({ err: error, requestId: input.requestId }, 'gemini failed');
      global.__aiDegraded__ = true;
      return postProcess(deriveFromHeuristic(input), input, false);
    }
  }

  global.__aiDegraded__ = true;
  return postProcess(deriveFromHeuristic(input), input, false);
};

export const getGeminiDebugResult = async () => {
  const started = Date.now();
  const sample = await analyzeWithGemini({
    url: 'https://google.com',
    hostname: 'google.com',
    path: '/',
    queryParams: {},
    heuristicScore: 0,
    heuristicSignals: {
      typosquat: 0,
      suspiciousTLD: 0,
      ipAsHostname: 0,
      longSubdomains: 0,
      suspiciousKeywords: 0,
      encodedChars: 0,
      pathEntropy: 0,
      portAnomaly: 0,
      credentialInUrl: 0,
      idnHomoglyph: 0,
      excessiveDots: 0,
      numericSubdomain: 0,
      tldMismatch: 0,
      repeatingSegments: 0,
      queryParamCount: 0,
      redirectParam: 0
    },
    domainReputation: {
      riskScore: 0,
      reportCount: 0,
      trustScore: 90,
      is_whitelisted: true
    },
    urlType: 'standard',
    domain: 'google.com'
  });
  return {
    ai: Boolean(env.GEMINI_API_KEY),
    model: geminiModel,
    latencyMs: Date.now() - started,
    aiDegraded: sample.source !== 'gemini',
    sample
  };
};

export const pingGemini = async (): Promise<boolean> => {
  if (!createGenAiClient()) {
    return false;
  }
  try {
    await generateContentOnce({
      url: 'https://google.com',
      hostname: 'google.com',
      path: '/',
      queryParams: {},
      heuristicScore: 0,
      heuristicSignals: {
        typosquat: 0,
        suspiciousTLD: 0,
        ipAsHostname: 0,
        longSubdomains: 0,
        suspiciousKeywords: 0,
        encodedChars: 0,
        pathEntropy: 0,
        portAnomaly: 0,
        credentialInUrl: 0,
        idnHomoglyph: 0,
        excessiveDots: 0,
        numericSubdomain: 0,
        tldMismatch: 0,
        repeatingSegments: 0,
        queryParamCount: 0,
        redirectParam: 0
      },
      domainReputation: { riskScore: 0, reportCount: 0, trustScore: 90, is_whitelisted: true },
      urlType: 'standard',
      domain: 'google.com'
    });
    return true;
  } catch {
    return false;
  }
};
