import type { FileScanResult, ThreatReport, UrlScanResult } from '@/types/index';
import { getEffectiveGeminiKey } from '@/config';

export interface AppStatsResponse {
  totalScans: number;
  totalThreats: number;
  totalReports: number;
  totalFileScans: number;
  lastUpdated: string;
}

export interface RecentReportResponse {
  id: string;
  url: string;
  domain: string;
  category: string;
  description: string;
  status: string;
  createdAt: string;
}

export interface ApiErrorShape {
  message: string;
  status: number;
  retryAfterMs?: number;
  offline?: boolean;
}

const defaultBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:3001/api/v1';
const apiKey = import.meta.env.VITE_API_KEY!;

const getBaseUrl = (): string => {
  const runtime = localStorage.getItem('shield-api-base-url');
  return runtime ?? defaultBaseUrl;
};

const buildHeaders = async (): Promise<HeadersInit> => {
  const geminiKey = await getEffectiveGeminiKey();
  return {
    'Content-Type': 'application/json',
    'x-api-key': apiKey,
    ...(geminiKey ? { 'x-gemini-key': geminiKey } : {})
  };
};

const handleResponse = async <T>(response: Response): Promise<T> => {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error: ApiErrorShape = {
      message: body.message ?? body.error ?? 'Request failed',
      status: response.status,
      retryAfterMs: body.retryAfterMs
    };
    throw error;
  }
  return response.json() as Promise<T>;
};

const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
  try {
    const response = await fetch(`${getBaseUrl()}${path}`, init);
    return await handleResponse<T>(response);
  } catch (error) {
    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      throw { message: 'No internet connection - using last known data', status: 0, offline: true } as ApiErrorShape;
    }
    throw error;
  }
};

export const api = {
  setBaseUrl: (url: string) => {
    localStorage.setItem('shield-api-base-url', url.replace(/\/+$/, ''));
  },
  scanUrl: (payload: { url: string; tabId?: number; sessionId?: string }) =>
    buildHeaders().then((headers) => request<UrlScanResult>('/scan/url', { method: 'POST', headers, body: JSON.stringify(payload) })),
  explainUrl: (payload: { url: string; force?: boolean }) =>
    buildHeaders().then((headers) => request<UrlScanResult>('/ai/explain', { method: 'POST', headers, body: JSON.stringify(payload) })),
  reportSite: (payload: ThreatReport) =>
    buildHeaders().then((headers) => request<{ id: string; status: 'pending' | 'already_reported'; message: string }>('/reports', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    })),
  getStats: () => request<AppStatsResponse>('/stats', { headers: { 'x-api-key': apiKey } }),
  getRecentReports: () => request<RecentReportResponse[]>('/reports/recent', { headers: { 'x-api-key': apiKey } }),
  scanFileMultipart: async (file: File, sourceUrl: string): Promise<FileScanResult> => {
    const form = new FormData();
    form.append('file', file);
    form.append('sourceUrl', sourceUrl);
    const geminiKey = await getEffectiveGeminiKey();
    const response = await fetch(`${getBaseUrl()}/scan/file`, {
      method: 'POST',
      headers: { 'x-api-key': apiKey, ...(geminiKey ? { 'x-gemini-key': geminiKey } : {}) },
      body: form
    });
    return handleResponse<FileScanResult>(response);
  }
};
