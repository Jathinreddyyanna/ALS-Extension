import { z } from 'zod'

export const ReportSchema = z.object({
  url: z.string().url({ message: 'Must be a valid URL' }).max(2048),
  category: z.enum(['phishing', 'scam', 'malware', 'redirect', 'popup_abuse', 'other']),
  description: z.string().max(500).optional(),
  signals: z.record(z.unknown()).optional(),
})

const PageContextSchema = z.object({
  title: z.string().max(120).optional().default(''),
  headings: z.array(z.string().max(120)).max(6).optional().default([]),
  bodyPreview: z.string().max(1000).optional().default(''),
  formSignals: z.array(z.string().max(120)).max(8).optional().default([]),
  actionTexts: z.array(z.string().max(80)).max(8).optional().default([]),
  popupSignals: z.object({
    fixedOverlayCount: z.number().int().min(0).max(999).optional().default(0),
    iframeCount: z.number().int().min(0).max(999).optional().default(0),
    externalLinkCount: z.number().int().min(0).max(9999).optional().default(0),
    newWindowHints: z.number().int().min(0).max(999).optional().default(0),
  }).optional(),
  pageSignals: z.object({
    sensitiveFieldCount: z.number().int().min(0).max(999).optional().default(0),
    hiddenSensitiveFieldCount: z.number().int().min(0).max(999).optional().default(0),
    hiddenFormCount: z.number().int().min(0).max(999).optional().default(0),
    loginButtonCount: z.number().int().min(0).max(999).optional().default(0),
    externalFormActionCount: z.number().int().min(0).max(999).optional().default(0),
    insecureFormActionCount: z.number().int().min(0).max(999).optional().default(0),
    brandMismatchCount: z.number().int().min(0).max(999).optional().default(0),
    suspiciousScriptCount: z.number().int().min(0).max(999).optional().default(0),
    autoRedirectHintCount: z.number().int().min(0).max(999).optional().default(0),
    metaRefreshCount: z.number().int().min(0).max(999).optional().default(0),
  }).optional(),
})

// Flexible signals that accept any numeric values
export const UrlScanSchema = z.object({
  url: z.string().url().max(2048),
  signals: z.record(z.number()).optional().default({}),
  pageContext: PageContextSchema.optional(),
})

export const FileScanSchema = z.object({
  filename:       z.string().max(255),
  extension:      z.string().max(20),
  mimeType:       z.string().max(100),
  sizeBytes:      z.number().positive(),
  sourceUrl:      z.string().url().max(2048),
  contentSnippet: z.string().max(2000).optional(),
})

export type ReportInput   = z.infer<typeof ReportSchema>
export type UrlScanInput  = z.infer<typeof UrlScanSchema>
export type FileScanInput = z.infer<typeof FileScanSchema>
