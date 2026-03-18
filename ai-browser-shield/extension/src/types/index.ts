export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';

export interface UrlScanResult {
  url: string;
  domain: string;
  riskScore: number;
  riskLevel: RiskLevel;
  explanation: string;
  aiExplanation?: string;
  keyIndicators: string[];
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
  modelUsed?: string;
  processedMs: number;
  urlType: string;
  source?: string;
  skip?: boolean;
  reason?: string;
}

export interface ThreatEvent {
  id: string;
  eventType: 'url_threat' | 'file_scan';
  domain: string;
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  aiExplanation?: string;
  verdict?: Verdict;
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
  category: 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'ad_abuse' | 'data_exfil' | 'crypto_mining' | 'other';
  description: string;
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
}

export type MessageType =
  | 'ANALYZE_URL'
  | 'URL_RESULT'
  | 'POPUP_ATTEMPT'
  | 'REDIRECT_WARNING'
  | 'DOWNLOAD_WARNING'
  | 'ALLOW_DOWNLOAD'
  | 'FILE_SCAN_RESULT'
  | 'SHOW_OVERLAY'
  | 'HIDE_OVERLAY';

export interface ChromeMessage {
  type: MessageType;
  payload?: unknown;
}
