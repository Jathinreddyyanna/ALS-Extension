export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ThreatCategory = 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'other'
export type EventType = 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block' | 'email_phishing'
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

export interface EmailScanInput {
  subject: string
  from: string
  fromEmail?: string
  to?: string
  body: string
  links: string[]
  platform: 'gmail' | 'whatsapp' | 'telegram'
}

export interface EmailAnalysis {
  riskLabel: EmailRiskLabel
  finalScore: number
  explanation: string
  platform: string
  detectedPatterns: string[]
  subject: string
  from: string
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

export interface PageContextSnapshot {
  title: string
  headings: string[]
  bodyPreview: string
  formSignals: string[]
  actionTexts: string[]
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
  | 'GET_PAGE_CONTEXT'
  | 'EMAIL_CONTENT_UPDATE'
  | 'EMAIL_ANALYSIS_RESULT'
  | 'REDIRECT_WARNING'
  | 'DOWNLOAD_WARNING'
  | 'FILE_SCAN_RESULT'
  | 'SHOW_OVERLAY'
  | 'HIDE_OVERLAY'

export interface ChromeMessage {
  type: MessageType
  payload?: unknown
}
