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
