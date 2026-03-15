import { z } from 'zod'

export const ReportSchema = z.object({
  url: z.string().url({ message: 'Must be a valid URL' }).max(2048),
  category: z.enum(['phishing', 'scam', 'malware', 'redirect', 'popup_abuse', 'other']),
  description: z.string().max(500).optional(),
  signals: z.record(z.unknown()).optional(),
})

// Flexible signals that accept any numeric values
export const UrlScanSchema = z.object({
  url: z.string().url().max(2048),
  signals: z.record(z.number()).optional().default({}),
  force: z.boolean().optional().default(false),
})

export const FileScanSchema = z.object({
  filename:          z.string().max(255),
  extension:         z.string().max(20),
  mimeType:          z.string().max(100),
  sizeBytes:         z.number().nonnegative(),
  sourceUrl:         z.string().max(2048),
  sourceDomain:      z.string().max(253).optional().default(''),
  domainRiskScore:   z.number().min(0).max(100).optional().default(0),
  domainReportCount: z.number().min(0).optional().default(0),
  domainCategories:  z.array(z.string()).optional().default([]),
  contentSnippet:    z.string().max(2000).optional(),
})

export const ThreatEventSchema = z.object({
  id: z.string().optional(),
  eventType: z.enum(['url_threat', 'redirect_chain', 'popup_abuse', 'download_intercept', 'file_scan', 'ad_block']),
  domain: z.string().min(1).max(255),
  url: z.string().max(2048),
  riskScore: z.number().int().min(0).max(100),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  aiExplanation: z.string().max(5000).optional(),
  source: z.string().max(100).optional(),
  verdict: z.enum(['SAFE', 'SUSPICIOUS', 'MALICIOUS']).optional(),
  timestamp: z.number().optional(),
  metadata: z.record(z.unknown()).optional(),
})

export type ReportInput   = z.infer<typeof ReportSchema>
export type UrlScanInput  = z.infer<typeof UrlScanSchema>
export type FileScanInput = z.infer<typeof FileScanSchema>
export type ThreatEventInput = z.infer<typeof ThreatEventSchema>
