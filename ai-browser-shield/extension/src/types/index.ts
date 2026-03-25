export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
export type ContentCategory = 'streaming' | 'download' | 'adult' | 'financial' | 'login' | 'unknown';

export interface RuntimeSignalSummary {
  popupCount: number;
  redirectCount: number;
  hiddenIframeCount: number;
  overlayCount: number;
  scriptInjectionCount: number;
  suspiciousFormCount: number;
  domMutationCount: number;
  passwordFieldCount?: number;
  creditCardFieldCount?: number;
  earlyUnloadCount?: number;
  jsRedirectCount?: number;
  metaRefreshCount?: number;
}

export interface ActivityFeedItem {
  type: string;
  timestamp: number;
  detail: string;
}

export interface RiskHistorySnapshot {
  timestamp: number;
  riskScore: number;
  riskLevel: RiskLevel;
  signals: RuntimeSignalSummary;
}

export interface DomainReputation {
  domain: string;
  reportCount: number;
  averageRisk: number;
  lastSeen: number;
}

export interface PatternFlags {
  phishingPattern: boolean;
  redirectTrap: boolean;
  increasingRiskTrend: boolean;
}

export interface SensitiveDataRisk {
  detected: boolean;
  passwordFields: number;
  creditCardFields: number;
  level: 'none' | 'warning' | 'high';
  message: string;
}

export interface UrlScanResult {
  url: string;
  finalUrl?: string;
  redirectChain?: string[];
  domain: string;
  riskScore: number;
  riskLevel: RiskLevel;
  explanation: string;
  aiExplanation?: string;
  keyIndicators: string[];
  positives?: string[];
  warnings?: string[];
  recommendedAction: 'allow' | 'warn' | 'block' | 'quarantine';
  confidence: number;
  category: string;
  categories?: string[];
  verdict?: 'safe' | 'suspicious' | 'malicious' | 'quarantine';
  heuristic: number;
  dbRiskScore: number;
  dbReportCount: number;
  cached: boolean;
  aiDegraded?: boolean;
  aiSource?: 'gemini' | 'heuristic';
  aiUsed?: boolean;
  modelUsed?: string;
  processedMs: number;
  urlType: string;
  source?: string;
  signalsUsed?: string[];
  trustSignals?: string[];
  contentCategory?: ContentCategory;
  behaviorRisk?: number;
  runtimeRisk?: number;
  domRisk?: number;
  interactionRisk?: number;
  warningsEnhanced?: string[];
  allowlisted?: boolean;
  trustedDomain?: boolean;
  reputationStatus?: 'known_safe' | 'known_threat' | 'unknown' | 'community_flagged';
  decisionBasis?: string;
  skip?: boolean;
  reason?: string;
  sources?: string[];
  confidenceLevel?: 'high' | 'medium' | 'low';
  threatSource?: 'google' | 'internal' | 'multi';
  analysisDepth?: 'fast' | 'full';
  safeBrowsingMatched?: boolean;
  safeBrowsingThreatTypes?: string[];
  signals?: RuntimeSignalSummary;
  activityLog?: ActivityFeedItem[];
  modelStatus?: 'active' | 'degraded' | 'offline';
  tabId?: number;
  bypassed?: boolean;
  history?: RiskHistorySnapshot[];
  reputation?: DomainReputation | null;
  patternFlags?: PatternFlags;
  sensitiveDataRisk?: SensitiveDataRisk;
}

export interface ThreatEvent {
  id: string;
  eventType: 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block';
  domain: string;
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  aiExplanation?: string;
  verdict?: Verdict;
  source?: string;
  timestamp: number;
}

export interface FileScanResult {
  verdict: Verdict;
  confidence: number;
  explanation: string;
  indicators: string[];
  recommended_action: string;
  recommendedAction?: 'allow' | 'warn' | 'block';
  sourceRisk?: 'safe' | 'suspicious' | 'dangerous';
  sourceDomain?: string;
  domainRiskScore?: number;
  domainReportCount?: number;
  fileScanId?: string;
  processedMs: number;
}

export interface ThreatReport {
  url: string;
  category: 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'ad_abuse' | 'data_exfil' | 'crypto_mining' | 'piracy' | 'other';
  description: string;
}

export interface FeedbackPayload {
  url: string;
  verdict: RiskLevel | Verdict | string;
  userAction: 'allowed' | 'blocked' | 'reported' | 'dismissed' | 'continued';
}

export type ThreatCategory = ThreatReport['category'];
export type EventType = 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block';

export interface DomainScore {
  domain: string;
  riskScore: number;
  reportCount: number;
  categories: string[];
  aiSummary?: string | null;
  aiThreatLevel?: string | null;
  aiRecommendation?: string | null;
  lastUpdated: string;
}

export interface TrackerTabStats {
  tabId: number;
  tabUrl: string;
  tabDomain: string;
  ads: number;
  trackers: number;
  fingerprinters: number;
  social: number;
  cryptominers: number;
  bounceTrackers: number;
  total: number;
  bandwidthSavedBytes: number;
  lastUpdated: number;
}

export interface TrackerSessionStats {
  totalBlocked: number;
  ads: number;
  trackers: number;
  fingerprinters: number;
  social: number;
  cryptominers: number;
  bounceTrackers: number;
  bandwidthSavedBytes: number;
  sitesProtected: number;
  since: number;
}

export interface CommunityReport {
  domain: string;
  category: string;
  reports: number;
  riskScore: number;
  lastSeen: string;
}

export interface SignalMap {
  typosquatScore: number;
  suspiciousTLD: number;
  ipAsHostname: number;
  longSubdomains: number;
  suspiciousKeywords: number;
  encodedChars: number;
  pathEntropy: number;
  portAnomaly: number;
  hiddenIframes?: number;
  overlayTrap?: number;
  fakePlayButtons?: number;
  clickInterception?: number;
  popupFrequency?: number;
  suspiciousFormCount?: number;
  autoSubmitForms?: number;
  redirectChains?: number;
  domRisk?: number;
  interactionRisk?: number;
  [key: string]: number | undefined;
}

export type MessageType =
  | 'ANALYZE_URL'
  | 'URL_RESULT'
  | 'POPUP_ATTEMPT'
  | 'DOM_SIGNALS_COLLECTED'
  | 'PRECLICK_RISK_EVALUATED'
  | 'PRECLICK_NAVIGATION_DECISION'
  | 'REDIRECT_WARNING'
  | 'DOWNLOAD_WARNING'
  | 'ALLOW_DOWNLOAD'
  | 'FILE_SCAN_RESULT'
  | 'SHOW_OVERLAY'
  | 'HIDE_OVERLAY'
  | 'VAULT_CREATE'
  | 'VAULT_UNLOCK'
  | 'VAULT_LOCK'
  | 'VAULT_GET_STATE'
  | 'VAULT_ADD_ENTRY'
  | 'VAULT_UPDATE_ENTRY'
  | 'VAULT_DELETE_ENTRY'
  | 'VAULT_SEARCH'
  | 'VAULT_GET_AUDIT'
  | 'VAULT_EXPORT'
  | 'VAULT_IMPORT'
  | 'VAULT_AUTOFILL_REQUEST'
  | 'VAULT_SAVE_ACCEPTED'
  | 'VAULT_MARK_USED'
  | 'VAULT_DO_AUTOFILL'
  | 'VAULT_AUTOFILL_BLOCKED'
  | 'GET_SCAN_DATA'
  | 'SCAN_UPDATED'
  | 'BYPASS_FOR_TAB'
  | 'ALLOWLIST_DOMAIN'
  | 'RESCAN_TAB'
  | 'REPORT_SITE'
  | 'SENSITIVE_DATA_RISK'
  | 'EARLY_REDIRECT_ATTEMPT'
  | 'DANGEROUS_API_CALL';

export interface ChromeMessage {
  type: MessageType;
  payload?: unknown;
}

export * from './vault';
