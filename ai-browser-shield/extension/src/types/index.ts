export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ThreatCategory = 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'other'
export type EventType = 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block'

export interface ThreatEvent {
  id: string
  eventType: EventType
  domain: string
  url: string
  riskScore: number
  riskLevel: RiskLevel
  aiExplanation?: string
  source?: string
  verdict?: Verdict
  timestamp: number
}

export interface FileScanResult {
  verdict: Verdict
  confidence: number
  explanation: string
  recommendedAction: 'allow' | 'warn' | 'block'
  indicators: string[]
  sourceRisk?: 'safe' | 'suspicious' | 'dangerous'
  sourceDomain?: string
  domainRiskScore?: number
  domainReportCount?: number
}

export interface UrlScanResult {
  explanation: string
  riskLevel: RiskLevel
  recommendedAction: 'allow' | 'warn' | 'block'
  confidence: number
  keyIndicators?: string[]
  riskScore: number
  heuristic?: number
  dbRiskScore?: number
  dbReportCount?: number
  source?: string
  db?: {
    reportCount: number
    categories: string[]
    domainRiskScore: number
    lastSeen: string | null
  }
  cached: boolean
}

export interface ThreatReport {
  url: string
  category: ThreatCategory
  description?: string
  signals?: Record<string, unknown>
}

export interface DomainScore {
  domain: string
  riskScore: number
  reportCount: number
  categories: string[]
  aiSummary?: string | null
  aiThreatLevel?: string | null
  aiRecommendation?: string | null
  lastUpdated: string
}

export interface TrackerTabStats {
  tabId: number
  tabUrl: string
  tabDomain: string
  ads: number
  trackers: number
  fingerprinters: number
  social: number
  cryptominers: number
  bounceTrackers: number
  total: number
  bandwidthSavedBytes: number
  lastUpdated: number
}

export interface TrackerSessionStats {
  totalBlocked: number
  ads: number
  trackers: number
  fingerprinters: number
  social: number
  cryptominers: number
  bounceTrackers: number
  bandwidthSavedBytes: number
  sitesProtected: number
  since: number
}

export interface CommunityReport {
  domain: string
  category: string
  reports: number
  riskScore: number
  lastSeen: string
}

export interface SignalMap {
  typosquatScore: number
  suspiciousTLD: number
  ipAsHostname: number
  longSubdomains: number
  suspiciousKeywords: number
  encodedChars: number
  pathEntropy: number
  portAnomaly: number
}

// Chrome runtime message types
export type MessageType =
  | 'ANALYZE_URL'
  | 'URL_RESULT'
  | 'POPUP_ATTEMPT'
  | 'REDIRECT_WARNING'
  | 'DOWNLOAD_WARNING'
  | 'ALLOW_DOWNLOAD'
  | 'FILE_SCAN_RESULT'
  | 'SHOW_OVERLAY'
  | 'HIDE_OVERLAY'

export interface ChromeMessage {
  type: MessageType
  payload?: unknown
}
