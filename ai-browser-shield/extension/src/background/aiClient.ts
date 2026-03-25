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
      try {
        await res.text();
      } catch {
        // Ignore failed response body reads.
      }
      return null;
    }

    const data = await res.json();
    return data;
  } catch (err: any) {
    void err
    return null;
  }
}
