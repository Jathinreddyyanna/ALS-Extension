import { getEffectiveApiBaseUrl, getEffectiveApiKey } from '../config';

/**
 * Calls the AI explanation service to analyze a URL and its signals.
 * Returns null if the service is unavailable or returns an error,
 * allowing the caller to fall back to heuristics.
 */
export async function explainThreat(url: string, signals: any, popupAnalysis?: any) {
  try {
    const baseUrl = await getEffectiveApiBaseUrl();
    const apiKey = await getEffectiveApiKey();

    const version = (import.meta as any).env.VITE_EXTENSION_VERSION || '1.0.0';

    const res = await fetch(`${baseUrl}/ai/explain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Extension-Version': version,
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
      },
      body: JSON.stringify({
        url,
        signals,
        popupRedirect: popupAnalysis,
        force: true,
      }),
    });

    if (!res.ok) {
      let errorBody = '';
      try {
        errorBody = await res.text();
      } catch (e) {
        errorBody = '(failed to read body)';
      }
      console.warn(`[AI Explain] HTTP ${res.status}:`, errorBody);
      return null;
    }

    const data = await res.json();
    return data;
  } catch (err: any) {
    if (err.name === 'AbortError') {
      console.warn('[AI Explain] Request timed out');
    } else {
      console.warn('[AI Explain] Network error:', err.message || err);
    }
    return null;
  }
}
