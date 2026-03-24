import { z } from 'zod';
import { env } from '../config';

const signalsSchema = z.record(z.number());
const httpUrlSchema = z.string()
  .trim()
  .min(1)
  .max(env.MAX_URL_LENGTH)
  .refine((value) => /^https?:\/\//i.test(value), 'URL must use http or https');

export const scanUrlSchema = z.object({
  url: httpUrlSchema,
  signals: signalsSchema.optional(),
  sessionId: z.string().min(1).max(128).optional(),
  tabId: z.number().int().optional(),
  requestContext: z.object({
    referrer: z.string().optional(),
    tabCount: z.number().int().optional(),
    timeOnPage: z.number().nonnegative().optional()
  }).strip().optional()
}).strip();

export const scanFileJsonSchema = z.object({
  filename: z.string().min(1),
  mimeType: z.string().min(1),
  sizeBytes: z.coerce.number().int().nonnegative(),
  sourceUrl: z.string().min(1),
  base64Content: z.string().optional(),
  chrome_download_id: z.string().optional(),
  sessionId: z.string().optional()
}).strip();

export const reportSchema = z.object({
  url: httpUrlSchema,
  category: z.enum(['phishing', 'scam', 'malware', 'redirect', 'popup_abuse', 'ad_abuse', 'data_exfil', 'crypto_mining', 'piracy', 'other']),
  description: z.string().optional().default(''),
  signals: signalsSchema.optional(),
  domain: z.string().optional(),
  sessionId: z.string().optional()
}).strip();

export const downloadActionSchema = z.object({
  chrome_download_id: z.string().min(1),
  sessionId: z.string().optional()
}).strip();

export const aiExplainSchema = z.object({
  url: httpUrlSchema,
  signals: signalsSchema.optional(),
  popupRedirect: z.object({
    popupCount: z.number().int().nonnegative(),
    redirectCount: z.number().int().nonnegative(),
    riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    flags: z.array(z.string()).max(20)
  }).strip().optional(),
  force: z.boolean().optional()
}).strip();

export const emailSecuritySchema = z.object({
  emailBody: z.string().min(1),
  senderEmail: z.string().email(),
  subject: z.string().min(1)
}).strip();

export const domainParamSchema = z.object({
  domain: z.string().min(1)
}).strip();

export const adminConfirmSchema = z.object({
  verdict: z.enum(['confirmed', 'rejected']),
  notes: z.string().optional(),
  overrideRiskScore: z.number().min(0).max(100).optional()
}).strip();
