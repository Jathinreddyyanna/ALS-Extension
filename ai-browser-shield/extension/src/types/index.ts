export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ThreatCategory = 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'other'
export type EventType = 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block'
export type EmailRiskLabel = 'safe' | 'suspicious' | 'dangerous' | 'processing' | 'error'

export interface ThreatEvent {
  id: string
  eventType: EventType
  domain: string
  url: string
  riskScore: number
  riskLevel: RiskLevel
  aiExplanation?: string
  verdict?: Verdict
  timestamp: number
}

export interface FileScanResult {
  verdict: Verdict
  confidence: number
  explanation: string
  recommendedAction: 'keep' | 'quarantine' | 'delete'
  indicators: string[]
}

export interface UrlScanResult {
  explanation: string
  riskLevel: RiskLevel
  recommendedAction: 'allow' | 'warn' | 'block'
  confidence: number
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
  lastUpdated: string
}

export interface CommunityReport {
  domain: string
  category: string
  reports: number
  riskScore: number
  lastSeen: string
}

export interface EmailSnapshot {
  subject: string
  from: string
  fromEmail: string
  body: string
  links: string[]
  platform: 'gmail'
  timestamp: number | string | null
}

export interface EmailAnalysis {
  final_risk_label: EmailRiskLabel
  risk_label: EmailRiskLabel
  final_score: number
  platform: string
  explanation: string
  detected_patterns: string[]
  engine: 'remote-ml' | 'local-fallback'
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
  | 'PAGE_ANALYSIS'
  | 'POPUP_ATTEMPT'
  | 'REDIRECT_WARNING'
  | 'DOWNLOAD_WARNING'
  | 'FILE_SCAN_RESULT'
  | 'SHOW_OVERLAY'
  | 'HIDE_OVERLAY'
  | 'EMAIL_PREDICTION_RESULT'

export interface PageAnalysis {
  score: number
  signals: string[]
  counts: {
    urgentTerms: number
    suspiciousForms: number
    crossOriginForms: number
    hiddenForms: number
    loginButtons: number
    fakePopups: number
    externalScripts: number
    autoRedirects: number
  }
}

export interface ChromeMessage {
  type: MessageType
  payload?: unknown
}
