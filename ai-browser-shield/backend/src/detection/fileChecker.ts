import { SAFE_FILE_EXTENSIONS } from '../config/constants';

export interface FileCheckResult {
  indicators: string[];
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export const getExtension = (filename: string): string => {
  const parts = filename.toLowerCase().split('.');
  return parts.length > 1 ? parts.at(-1) ?? '' : '';
};

export const checkFileSafety = (input: {
  filename: string;
  mimeType: string;
  sizeBytes: number;
}): FileCheckResult => {
  const indicators: string[] = [];
  const extension = getExtension(input.filename);
  let riskScore = 0;

  if (!SAFE_FILE_EXTENSIONS.includes(extension as (typeof SAFE_FILE_EXTENSIONS)[number])) {
    indicators.push('extension_not_whitelisted');
    riskScore += 25;
  }
  if (input.sizeBytes === 0) {
    indicators.push('empty_file');
    riskScore += 30;
  }
  if (input.sizeBytes > 500 * 1024 * 1024) {
    indicators.push('oversized_file');
    riskScore += 15;
  }
  if (input.mimeType.includes('image/') && input.sizeBytes > 50 * 1024 * 1024) {
    indicators.push('image_size_anomaly');
    riskScore += 15;
  }
  if ((extension === 'exe' || extension === 'scr' || extension === 'msi') && !input.mimeType.includes('application/')) {
    indicators.push('mime_extension_mismatch');
    riskScore += 35;
  }
  if ((extension === 'pdf' && input.mimeType.includes('exe')) || (extension === 'jpg' && input.mimeType.includes('application/'))) {
    indicators.push('mime_extension_mismatch');
    riskScore += 35;
  }

  const riskLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW';
  return { indicators, riskScore, riskLevel };
};
