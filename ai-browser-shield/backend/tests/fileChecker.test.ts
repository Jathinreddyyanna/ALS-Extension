import { describe, expect, it } from 'vitest';
import { checkFileSafety } from '../src/detection/fileChecker';

describe('fileChecker', () => {
  it('flags empty files', () => {
    const result = checkFileSafety({ filename: 'payload.exe', mimeType: 'application/octet-stream', sizeBytes: 0 });
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it('flags mime mismatch', () => {
    const result = checkFileSafety({ filename: 'image.jpg', mimeType: 'application/x-msdownload', sizeBytes: 1024 });
    expect(result.indicators).toContain('mime_extension_mismatch');
  });
});
