import { describe, expect, it } from 'vitest';
import { parseAndNormalizeUrl } from '../src/detection/urlParser';

describe('urlParser', () => {
  it('skips browser internal urls', () => {
    const parsed = parseAndNormalizeUrl('chrome://extensions');
    expect(parsed.skip).toBe(true);
  });

  it('handles file urls', () => {
    const parsed = parseAndNormalizeUrl('file:///Users/me/Downloads/invoice.html');
    expect(parsed.urlType).toBe('file');
  });

  it('extracts blob origin', () => {
    const parsed = parseAndNormalizeUrl('blob:https://example.com/abc');
    expect(parsed.extractedBlobOrigin).toContain('https://example.com/abc');
  });

  it('handles private ipv6', () => {
    const parsed = parseAndNormalizeUrl('http://[fc00::1]');
    expect(parsed.urlType).toBe('private_ip');
  });
});
