/**
 * ML-Powered Email Analysis API Client
 * Connects to Flask ML backend for phishing detection
 * 
 * Note: Using 127.0.0.1 instead of localhost is more reliable for Chrome extensions
 * because localhost can sometimes resolve differently in sandboxed contexts.
 */

const ML_API_URL = 'http://127.0.0.1:5000';
const API_TIMEOUT_MS = 8000;

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit = {}, timeoutMs: number = API_TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timeoutId);
  }
}

export interface MLAnalysisRequest {
  text: string;
  sender: string;
  subject: string;
  is_spam?: boolean;
}

export interface MLAnalysisResult {
  risk_score: number;
  label: 'phishing' | 'legitimate' | 'unknown';
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  confidence: number;
  attack_type?: string;
  reasons?: string[];
  sender_trust?: 'new' | 'known' | 'flagged' | string;
  explanation: {
    risk_level: string;
    reasons: string[];
    consequences: string[];
    actions: string[];
  };
  detected_features?: string[];
}

/**
 * Analyze email using ML model backend
 */
export async function analyzeEmailML(emailData: MLAnalysisRequest): Promise<MLAnalysisResult> {
  try {
    console.log('[API] Starting email analysis request to:', `${ML_API_URL}/analyze-email`);
    
    const response = await fetchWithTimeout(`${ML_API_URL}/analyze-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData),
    });

    console.log('[API] Response received with status:', response.status);
    
    if (!response.ok) {
      console.error('[API] API returned error status:', response.status, response.statusText);
      throw new Error(`ML API error: ${response.status}`);
    }

    const result = await response.json();
    console.log('[API] Analysis result:', result.risk_score, result.label);
    return result;

  } catch (error) {
    console.error('[API] ML analysis failed with error:', error instanceof Error ? error.message : String(error));
    console.error('[API] Error details:', error);

    // Return cautious default on error so failure is never shown as "safe".
    return {
      risk_score: 35,
      label: 'unknown',
      risk_level: 'UNKNOWN',
      confidence: 0,
      attack_type: 'Unknown Pattern',
      reasons: ['Unable to analyze email - ML backend not responding'],
      sender_trust: 'new',
      explanation: {
        risk_level: '⚠️ Analysis unavailable',
        reasons: ['Unable to analyze email - ML backend not responding'],
        consequences: ['Analysis service temporarily unavailable'],
        actions: ['✓ Verify sender manually', '✗ Be cautious with links']
      }
    };
  }
}

/**
 * Check if ML backend is running
 */
export async function checkMLBackendHealth(): Promise<boolean> {
  try {
    console.log('[API] Checking backend health at:', `${ML_API_URL}/health`);
    const response = await fetchWithTimeout(`${ML_API_URL}/health`, {
      method: 'GET',
    }, 2500);

    console.log('[API] Health check response status:', response.status);
    return response.ok;
  } catch (error) {
    console.error('[API] Health check failed:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

/**
 * Batch analyze multiple emails (optional)
 */
export async function batchAnalyzeEmails(
  emails: MLAnalysisRequest[]
): Promise<{ total: number; results: any[] }> {
  try {
    const response = await fetchWithTimeout(`${ML_API_URL}/batch-analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ emails }),
    });

    if (!response.ok) {
      throw new Error(`Batch analysis failed: ${response.status}`);
    }

    return await response.json();

  } catch (error) {
    console.error('Batch analysis failed:', error);
    return { total: 0, results: [] };
  }
}
