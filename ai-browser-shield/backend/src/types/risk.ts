export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'

export type ThreatCategory =
  | 'phishing'
  | 'scam'
  | 'malware'
  | 'redirect'
  | 'popup_abuse'
  | 'other'

export type EventType =
  | 'url_threat'
  | 'redirect_chain'
  | 'popup_abuse'
  | 'download_intercept'
  | 'file_scan'
  | 'ad_block'

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
}

export interface UrlScanResult {
  explanation: string
  riskLevel: RiskLevel
  recommendedAction: 'allow' | 'warn' | 'block'
  confidence: number
  keyIndicators?: string[]
  riskScore?: number
  source?: string
  db?: {
    reportCount: number
    categories: string[]
    domainRiskScore: number
    lastSeen: string | null
  }
  cached: boolean
}

export interface DomainScore {
  domain: string
  riskScore: number
  reportCount: number
  categories: string[]
  lastUpdated: string
}

