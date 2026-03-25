import { env } from '../config';
import { logger } from '../utils/logger';

export interface EmailMlPredictionInput {
  subject: string;
  sender: string;
  body: string;
  links: string[];
  hasAttachments: boolean;
  attachmentNames?: string[];
}

export interface EmailMlPredictionResult {
  phishingProbability: number;
  decision: 'SAFE' | 'WARNING' | 'BLOCK';
  confidence: number;
  topFeatures: string[];
}

export interface EmailMlHealthResult {
  status: string;
  modelLoaded: boolean;
  error?: string;
}

const normalizeBaseUrl = () => env.FASTAPI_BACKEND_URL.replace(/\/+$/, '');

/**
 * Query the FastAPI email phishing model. Returns null on timeout or service failure.
 */
export async function predictEmailRisk(input: EmailMlPredictionInput): Promise<EmailMlPredictionResult | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.FASTAPI_TIMEOUT_MS);

  try {
    const response = await fetch(`${normalizeBaseUrl()}/predict/email`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        subject: input.subject,
        sender: input.sender,
        body: input.body,
        links: input.links,
        has_attachments: input.hasAttachments,
        attachment_names: input.attachmentNames ?? []
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      logger.warn({ status: response.status }, 'email ml backend returned non-ok status');
      return null;
    }

    const payload = await response.json() as {
      phishing_probability?: number;
      decision?: 'SAFE' | 'WARNING' | 'BLOCK';
      confidence?: number;
      top_features?: string[];
    };
    if (
      typeof payload.phishing_probability !== 'number' ||
      (payload.decision !== 'SAFE' && payload.decision !== 'WARNING' && payload.decision !== 'BLOCK') ||
      typeof payload.confidence !== 'number' ||
      !Array.isArray(payload.top_features)
    ) {
      logger.warn({ payload }, 'email ml backend returned invalid payload');
      return null;
    }

    return {
      phishingProbability: Math.max(0, Math.min(1, payload.phishing_probability)),
      decision: payload.decision,
      confidence: Math.max(0.01, Math.min(1, payload.confidence)),
      topFeatures: payload.top_features.map((item) => String(item)).filter(Boolean).slice(0, 5)
    };
  } catch (error) {
    logger.warn({ err: error }, 'email ml backend request failed');
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Query FastAPI health so the Node health endpoint can expose email ML readiness.
 */
export async function getEmailMlHealth(): Promise<EmailMlHealthResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.FASTAPI_TIMEOUT_MS);

  try {
    const response = await fetch(`${normalizeBaseUrl()}/health`, {
      method: 'GET',
      signal: controller.signal
    });
    if (!response.ok) {
      return { status: 'degraded', modelLoaded: false, error: `status_${response.status}` };
    }
    const payload = await response.json() as { status?: string; model_loaded?: boolean; error?: string };
    return {
      status: typeof payload.status === 'string' ? payload.status : 'degraded',
      modelLoaded: Boolean(payload.model_loaded),
      error: typeof payload.error === 'string' ? payload.error : undefined
    };
  } catch (error) {
    return {
      status: 'degraded',
      modelLoaded: false,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    clearTimeout(timeout);
  }
}
