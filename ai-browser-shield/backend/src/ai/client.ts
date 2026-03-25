import { GoogleGenerativeAI } from '@google/generative-ai';
import { env } from '../config';
import { analyzeWithGemini } from '../services/ai.service';
import { logger } from '../utils/logger';
import { buildEmailScanPrompt } from './prompts';

const EMAIL_MODEL_FALLBACK_CHAIN = Array.from(new Set([
  env.GEMINI_MODEL.replace(/^models\//, '').trim() || 'gemini-flash-lite-latest',
  'gemini-flash-lite-latest',
  'gemini-2.5-flash-lite',
  'gemini-flash-latest'
]));

export interface UrlScanResult {
  explanation: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendedAction: 'allow' | 'warn' | 'block';
  confidence: number;
  keyIndicators: string[];
}

export interface FileScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  confidence: number;
  explanation: string;
  recommendedAction: 'keep' | 'quarantine' | 'delete';
  indicators: string[];
}

export interface EmailScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  confidence: number;
  explanation: string;
  attackType: string;
  recommendedAction: 'ignore' | 'report' | 'delete';
}

type EmailScanInput = {
  sender: string;
  subject: string;
  body: string;
  links: string[];
  localSignals: string[];
};

type RawEmailScanResult = {
  verdict?: string;
  confidence?: number;
  explanation?: string;
  attackType?: string;
  recommendedAction?: string;
};

const createClient = (): GoogleGenerativeAI | null => {
  const apiKey = env.GEMINI_API_KEY.trim();
  return apiKey ? new GoogleGenerativeAI(apiKey) : null;
};

const parseJson = <T>(raw: string): T | null => {
  try {
    const cleaned = raw
      .trim()
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/```\s*$/i, '')
      .trim();
    return JSON.parse(cleaned) as T;
  } catch {
    return null;
  }
};

const getFallbackUrlResult = (score: number): UrlScanResult => {
  if (score >= 80) {
    return {
      explanation: 'This website triggered multiple high-risk security signals and is consistent with phishing or malware patterns.',
      riskLevel: 'CRITICAL',
      recommendedAction: 'block',
      confidence: 0.7,
      keyIndicators: ['High-risk signals', 'Possible phishing', 'Credential theft risk']
    };
  }
  if (score >= 60) {
    return {
      explanation: 'This website has several suspicious characteristics and should be treated with caution.',
      riskLevel: 'HIGH',
      recommendedAction: 'warn',
      confidence: 0.6,
      keyIndicators: ['Suspicious URL', 'Unusual domain pattern']
    };
  }
  return {
    explanation: 'This website has some unusual patterns. Proceed carefully if asked for sensitive information.',
    riskLevel: 'MEDIUM',
    recommendedAction: 'warn',
    confidence: 0.5,
    keyIndicators: ['Minor suspicious signals']
  };
};

const getFallbackFileResult = (): FileScanResult => ({
  verdict: 'SUSPICIOUS',
  confidence: 0.4,
  explanation: 'AI file analysis is temporarily unavailable. Only open this file if you trust the source.',
  recommendedAction: 'quarantine',
  indicators: ['Analysis service unavailable']
});

const getFallbackEmailResult = (): EmailScanResult => ({
  verdict: 'SUSPICIOUS',
  confidence: 0.5,
  explanation: 'Deep email analysis is temporarily unavailable. Verify the sender and any links carefully.',
  attackType: 'Phishing',
  recommendedAction: 'report'
});

const normalizeEmailResult = (parsed: RawEmailScanResult | null): EmailScanResult | null => {
  if (!parsed?.verdict || !parsed.explanation) {
    return null;
  }

  const verdict = String(parsed.verdict).toUpperCase();
  const recommendedAction = String(parsed.recommendedAction ?? 'report').toLowerCase();
  if (!['SAFE', 'SUSPICIOUS', 'DANGEROUS'].includes(verdict)) {
    return null;
  }

  return {
    verdict: verdict as EmailScanResult['verdict'],
    confidence: Math.max(0, Math.min(1, Number(parsed.confidence ?? 0.5))),
    explanation: String(parsed.explanation).trim(),
    attackType: String(parsed.attackType ?? 'Phishing').trim() || 'Phishing',
    recommendedAction: ['ignore', 'report', 'delete'].includes(recommendedAction)
      ? (recommendedAction as EmailScanResult['recommendedAction'])
      : 'report'
  };
};

const generateEmailContent = async (input: EmailScanInput): Promise<string> => {
  const client = createClient();
  if (!client) {
    throw new Error('gemini_not_configured');
  }

  const prompt = buildEmailScanPrompt(input);

  for (const modelName of EMAIL_MODEL_FALLBACK_CHAIN) {
    try {
      const model = client.getGenerativeModel({
        model: modelName,
        generationConfig: {
          responseMimeType: 'application/json',
          temperature: 0.1,
          maxOutputTokens: 1024
        }
      });
      const result = await model.generateContent(prompt);
      const text = result.response.text();
      if (text.trim()) {
        return text;
      }
    } catch (error) {
      logger.warn({ err: error, modelName }, 'email gemini generation failed, trying fallback model');
    }
  }

  throw new Error('all_email_models_exhausted');
};

export async function analyzeUrl(url: string, signals: Record<string, number>, riskScore: number): Promise<UrlScanResult> {
  try {
    const result = await analyzeWithGemini({
      url,
      hostname: (() => {
        try {
          return new URL(url).hostname;
        } catch {
          return 'unknown';
        }
      })(),
      path: (() => {
        try {
          return new URL(url).pathname;
        } catch {
          return '/';
        }
      })(),
      queryParams: {},
      heuristicScore: riskScore,
      heuristicSignals: {
        typosquat: 0,
        suspiciousTLD: 0,
        ipAsHostname: 0,
        longSubdomains: 0,
        suspiciousKeywords: Number(signals.suspiciousKeywords ?? 0),
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
        redirectParam: Number(signals.redirectParam ?? 0)
      },
      domainReputation: {
        riskScore: 0,
        reportCount: 0,
        trustScore: 50,
        is_whitelisted: false
      },
      urlType: 'standard',
      domain: (() => {
        try {
          return new URL(url).hostname;
        } catch {
          return url;
        }
      })()
    });

    return {
      explanation: result.explanation,
      riskLevel: result.riskLevel,
      recommendedAction: result.recommendedAction === 'block' ? 'block' : result.recommendedAction === 'warn' ? 'warn' : 'allow',
      confidence: result.confidence,
      keyIndicators: result.keyIndicators
    };
  } catch (error) {
    logger.warn({ err: error, url }, 'URL AI wrapper failed, using fallback');
    return getFallbackUrlResult(riskScore);
  }
}

export async function analyzeFile(data: {
  filename: string;
  extension: string;
  mimeType: string;
  sizeBytes: number;
  sourceUrl: string;
  contentSnippet?: string;
}): Promise<FileScanResult> {
  try {
    const result = await analyzeWithGemini({
      url: data.sourceUrl,
      hostname: (() => {
        try {
          return new URL(data.sourceUrl).hostname;
        } catch {
          return 'unknown';
        }
      })(),
      path: '/',
      queryParams: {},
      heuristicScore: 35,
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
        trustScore: 50,
        is_whitelisted: false
      },
      fileData: {
        filename: data.filename,
        mimeType: data.mimeType,
        sizeBytes: data.sizeBytes,
        extension: data.extension,
        fileSampleBase64: data.contentSnippet
      },
      urlType: 'standard',
      domain: data.sourceUrl
    });

    return {
      verdict: result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH' ? 'MALICIOUS' : result.riskLevel === 'MEDIUM' ? 'SUSPICIOUS' : 'SAFE',
      confidence: result.confidence,
      explanation: result.explanation,
      recommendedAction: result.recommendedAction === 'quarantine' ? 'quarantine' : result.recommendedAction === 'block' ? 'delete' : 'keep',
      indicators: result.keyIndicators
    };
  } catch (error) {
    logger.warn({ err: error, filename: data.filename }, 'File AI wrapper failed, using fallback');
    return getFallbackFileResult();
  }
}

export async function analyzeEmail(data: EmailScanInput): Promise<EmailScanResult> {
  try {
    const raw = await generateEmailContent(data);
    const parsed = normalizeEmailResult(parseJson<RawEmailScanResult>(raw));
    if (!parsed) {
      logger.warn({ sender: data.sender }, 'Email AI response parsing failed, using fallback');
      return getFallbackEmailResult();
    }
    return parsed;
  } catch (error) {
    logger.warn({ err: error, sender: data.sender }, 'Email AI analysis failed, using fallback');
    return getFallbackEmailResult();
  }
}
