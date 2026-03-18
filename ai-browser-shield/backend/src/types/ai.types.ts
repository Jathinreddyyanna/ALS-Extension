import type { AiAssessment } from './scan.types';

export interface GeminiDebugResult {
  model: string;
  latencyMs: number;
  ai: boolean;
  sample: AiAssessment;
}
