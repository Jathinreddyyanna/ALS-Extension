import { describe, expect, it } from 'vitest';
import { parseAndNormalizeUrl } from '../src/detection/urlParser';
import { scoreUrl } from '../src/detection/urlScorer';

describe('urlScorer', () => {
  it('flags credentialInUrl signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('http://user:pass@evil.com'));
    expect(scored.signals.credentialInUrl).toBe(25);
  });

  it('flags idnHomoglyph signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('https://pаypal.com'));
    expect(scored.signals.idnHomoglyph).toBeGreaterThan(0);
  });

  it('flags tldMismatch signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('https://paypal.net'));
    expect(scored.signals.tldMismatch).toBeGreaterThan(0);
  });

  it('flags redirectParam signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('https://good.com/go?url=http://evil.com'));
    expect(scored.signals.redirectParam).toBe(10);
  });

  it('flags excessiveDots signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('http://a.b.c.d.e.f.g.evil.com'));
    expect(scored.signals.excessiveDots).toBe(5);
  });

  it('flags numericSubdomain signal', () => {
    const scored = scoreUrl(parseAndNormalizeUrl('http://123.456.evil.com'));
    expect(scored.signals.numericSubdomain).toBe(10);
  });

  it('covers all url types', () => {
    const urls = [
      'http://localhost:3000',
      'http://192.168.1.1',
      'http://[::1]:8080',
      'chrome://settings',
      'file:///Users/me/Downloads/invoice.html',
      'data:text/html;base64,SGVsbG8=',
      'blob:https://example.com/abc-123',
      'http://user:pass@evil.com',
      'https://pаypal.com',
      'https://example.com/path',
      'http://185.220.101.45/malware',
      `https://example.com/${'a'.repeat(3000)}`
    ];

    for (const url of urls) {
      const parsed = parseAndNormalizeUrl(url);
      if (!parsed.skip) {
        const scored = scoreUrl(parsed);
        expect(scored.score).toBeGreaterThanOrEqual(0);
      } else {
        expect(parsed.skip).toBe(true);
      }
    }
  });
});
