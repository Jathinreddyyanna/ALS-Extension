import { z } from 'zod';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RecommendedAction = 'allow' | 'warn' | 'block' | 'quarantine';
export type AiVerdict = 'safe' | 'suspicious' | 'malicious' | 'quarantine';
export type UrlType =
  | 'standard'
  | 'localhost'
  | 'private_ip'
  | 'ip_hostname'
  | 'idn'
  | 'file'
  | 'blob'
  | 'data'
  | 'browser_internal'
  | 'ftp'
  | 'internal';

export type Category =
  | 'phishing'
  | 'malware'
  | 'scam'
  | 'redirect'
  | 'popup_abuse'
  | 'ad_abuse'
  | 'crypto_mining'
  | 'data_exfil'
  | 'clean'
  | 'unknown'
  | 'other';

export interface UrlScoreSignals {
  typosquat: number;
  suspiciousTLD: number;
  ipAsHostname: number;
  longSubdomains: number;
  suspiciousKeywords: number;
  encodedChars: number;
  pathEntropy: number;
  portAnomaly: number;
  credentialInUrl: number;
  idnHomoglyph: number;
  excessiveDots: number;
  numericSubdomain: number;
  tldMismatch: number;
  repeatingSegments: number;
  queryParamCount: number;
  redirectParam: number;
}

export interface UrlScoreResult {
  score: number;
  riskLevel: RiskLevel;
  signals: UrlScoreSignals;
  indicators: string[];
}

export interface ParsedUrlResult {
  originalUrl: string;
  aiSafeUrl: string;
  normalizedUrl: string;
  truncatedForAi: boolean;
  urlType: UrlType;
  hostname: string;
  hostnameUnicode: string;
  domain: string;
  path: string;
  queryParams: Record<string, string>;
  port: string;
  protocol: string;
  isInternal: boolean;
  skip: boolean;
  skipReason?: string;
  notes: string[];
  hasCredentials: boolean;
  decodedUrl: string;
  extractedBlobOrigin?: string;
}

export interface AiDomainReputation {
  riskScore: number;
  reportCount: number;
  trustScore: number;
  is_whitelisted: boolean;
}

export interface AiPopupRedirectData {
  popupCount: number;
  redirectCount: number;
  riskLevel: RiskLevel;
  flags: string[];
}

export interface AiRequestContext {
  referrer?: string;
  tabCount?: number;
  timeOnPage?: number;
}

export interface AnalyzeWithGeminiInput {
  url: string;
  hostname: string;
  path: string;
  queryParams: Record<string, string>;
  heuristicScore: number;
  heuristicSignals: UrlScoreSignals;
  domainReputation: AiDomainReputation;
  popupRedirectData?: AiPopupRedirectData;
  fileData?: {
    filename: string;
    mimeType: string;
    sizeBytes: number;
    extension: string;
    fileSampleBase64?: string;
  };
  urlType: UrlType;
  requestContext?: AiRequestContext;
  requestId?: string;
  cacheKey?: string;
  domain?: string;
  userGeminiKey?: string;
}

export interface AiAssessment {
  riskLevel: RiskLevel;
  riskScore: number;
  confidence: number;
  recommendedAction: RecommendedAction;
  explanation: string;
  keyIndicators: string[];
  category: Category;
  categories?: string[];
  verdict?: AiVerdict;
  threatVector: 'url_structure' | 'domain_reputation' | 'behavior' | 'file' | 'unknown';
  isFalsePositiveRisk: boolean;
  suggestedWhitelist: boolean;
  source: 'gemini' | 'heuristic';
  modelUsed?: string;
  aiDegraded?: boolean;
  cached?: boolean;
}

export interface UrlScanResult {
  url: string;
  domain: string;
  riskScore: number;
  riskLevel: RiskLevel;
  explanation: string;
  aiExplanation?: string;
  keyIndicators: string[];
  recommendedAction: RecommendedAction;
  confidence: number;
  category: Category;
  categories?: string[];
  verdict?: AiVerdict;
  heuristic: number;
  dbRiskScore: number;
  dbReportCount: number;
  cached: boolean;
  aiDegraded?: boolean;
  aiSource?: 'gemini' | 'heuristic';
  modelUsed?: string;
  processedMs: number;
  urlType: UrlType;
  source?: string;
  skip?: boolean;
  reason?: string;
}

export const UrlScanResponseSchema = z.object({
  url: z.string(),
  domain: z.string(),
  riskScore: z.number().min(0).max(100),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  explanation: z.string(),
  keyIndicators: z.array(z.string()),
  recommendedAction: z.enum(['allow', 'warn', 'block', 'quarantine']),
  confidence: z.number().min(0).max(1),
  category: z.string(),
  categories: z.array(z.string()).optional(),
  verdict: z.enum(['safe', 'suspicious', 'malicious', 'quarantine']).optional(),
  heuristic: z.number(),
  dbRiskScore: z.number(),
  dbReportCount: z.number(),
  cached: z.boolean(),
  aiDegraded: z.boolean().optional(),
  aiSource: z.enum(['gemini', 'heuristic']).optional(),
  modelUsed: z.string().optional(),
  aiExplanation: z.string().optional(),
  processedMs: z.number(),
  urlType: z.string(),
  source: z.string().optional(),
  skip: z.boolean().optional(),
  reason: z.string().optional()
});

export const FileScanResponseSchema = z.object({
  verdict: z.enum(['SAFE', 'SUSPICIOUS', 'MALICIOUS']),
  confidence: z.number().min(0).max(1),
  explanation: z.string(),
  indicators: z.array(z.string()),
  recommended_action: z.string(),
  fileScanId: z.string().optional(),
  processedMs: z.number()
});
