import { beforeEach, describe, expect, it, vi } from 'vitest';
import { prisma } from '../src/db/client';

const {
  aggregateThreatIntelMock,
  generateExplanationMock,
  scoreExplanationConsistencyMock
} = vi.hoisted(() => ({
  aggregateThreatIntelMock: vi.fn(),
  generateExplanationMock: vi.fn(),
  scoreExplanationConsistencyMock: vi.fn()
}));

vi.mock('../src/services/threatIntel.service', () => ({
  aggregateThreatIntel: aggregateThreatIntelMock
}));

vi.mock('../src/services/explanation.service', () => ({
  generateExplanation: generateExplanationMock,
  scoreExplanationConsistency: scoreExplanationConsistencyMock
}));

import { performUrlScan } from '../src/services/scan.service';

describe('scan.service', () => {
  beforeEach(() => {
    aggregateThreatIntelMock.mockReset();
    generateExplanationMock.mockReset();
    scoreExplanationConsistencyMock.mockReset();

    aggregateThreatIntelMock.mockResolvedValue({
      isMalicious: false,
      sources: [],
      threatTypes: [],
      threatSource: 'internal',
      confidenceLevel: 'low',
      matchedProviders: []
    });

    generateExplanationMock.mockResolvedValue({
      content: {
        explanation: 'No known threats were confirmed for this page, but monitor it for redirects, downloads, or permission prompts.',
        keyIndicators: ['Baseline analysis'],
        positives: ['Secure HTTPS connection'],
        warnings: [],
        recommendation: 'allow'
      },
      aiUsed: false
    });

    scoreExplanationConsistencyMock.mockReturnValue(0.9);
  });

  it('short-circuits to CRITICAL when Google Safe Browsing matches', async () => {
    aggregateThreatIntelMock.mockResolvedValueOnce({
      isMalicious: true,
      sources: ['google_safe_browsing'],
      threatTypes: ['SOCIAL_ENGINEERING'],
      threatSource: 'google',
      confidenceLevel: 'high',
      matchedProviders: [{
        provider: 'google_safe_browsing',
        isMalicious: true,
        threatTypes: ['SOCIAL_ENGINEERING'],
        source: 'google_safe_browsing',
        confidenceLevel: 'high'
      }]
    });

    const result = await performUrlScan({ url: 'https://phish.example/login' });

    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.riskScore).toBe(100);
    expect(result.decisionBasis).toBe('google_safe_browsing');
    expect(result.threatSource).toBe('google');
    expect(result.safeBrowsingMatched).toBe(true);
    expect(result.safeBrowsingThreatTypes).toEqual(['SOCIAL_ENGINEERING']);
    expect(result.sources).toEqual(['google_safe_browsing']);
    expect(generateExplanationMock).not.toHaveBeenCalled();
  });

  it('keeps official banking domains LOW even without AI', async () => {
    const result = await performUrlScan({ url: 'https://onlinesbi.sbi.bank.in/' });

    expect(result.riskLevel).toBe('LOW');
    expect(result.decisionBasis).toBe('official_tld_verified');
    expect(result.positives).toContain('Secure HTTPS connection');
    expect(result.aiUsed).toBe(false);
    expect(result.threatSource).toBe('internal');
    expect(result.analysisDepth).toBe('full');
  });

  it('short-circuits to LOW for verified allowlisted domains', async () => {
    const result = await performUrlScan({ url: 'https://github.com/login' });

    expect(result.riskLevel).toBe('LOW');
    expect(result.allowlisted).toBe(true);
    expect(result.decisionBasis).toBe('verified_allowlist');
    expect(result.recommendedAction).toBe('allow');
  });

  it('elevates subdomain spoofing patterns to HIGH risk', async () => {
    generateExplanationMock.mockResolvedValueOnce({
      content: {
        explanation: 'This domain uses a trusted brand inside a deceptive subdomain chain.',
        keyIndicators: ['subdomain_spoofing', 'Possible impersonation'],
        positives: [],
        warnings: ['Suspicious domain structure', 'Possible impersonation'],
        recommendation: 'block'
      },
      aiUsed: false
    });

    const result = await performUrlScan({ url: 'https://google.com.evil.xyz/' });

    expect(result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL').toBe(true);
    expect(result.decisionBasis).toBe('subdomain_spoofing_detected');
    expect(result.signalsUsed).toContain('subdomain_spoofing');
    expect(result.warnings).toContain('Suspicious domain structure');
  });

  it('treats homoglyph brand impersonation as critical phishing risk', async () => {
    generateExplanationMock.mockResolvedValueOnce({
      content: {
        explanation: 'This domain appears to imitate a known brand using visually similar characters.',
        keyIndicators: ['homoglyph_attack', 'Possible impersonation'],
        positives: [],
        warnings: ['Homoglyph attack indicators', 'Possible impersonation'],
        recommendation: 'block'
      },
      aiUsed: false
    });

    const result = await performUrlScan({ url: 'https://paypaI.com/' });

    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.decisionBasis).toBe('homoglyph_or_punycode_detected');
    expect((result.signalsUsed ?? []).some((signal) => signal === 'punycode_domain' || signal === 'homoglyph_attack')).toBe(true);
  });

  it('survives reputation lookup failures and falls back cleanly', async () => {
    vi.mocked(prisma.domainScore.findUnique).mockRejectedValueOnce(new Error('db down'));

    const result = await performUrlScan({ url: 'https://dbfail.test/login' });

    expect(result.dbRiskScore).toBeGreaterThanOrEqual(0);
    expect(result.reputationStatus === 'unknown' || result.reputationStatus === 'community_flagged' || result.reputationStatus === 'known_safe' || result.reputationStatus === 'known_threat').toBe(true);
  });

  it('fails open to the internal engine when threat intel providers fail', async () => {
    aggregateThreatIntelMock.mockRejectedValueOnce(new Error('provider down'));

    const result = await performUrlScan({ url: 'https://fresh-example-domain123.com/' });

    expect(result.threatSource).toBe('internal');
    expect(result.safeBrowsingMatched).toBe(false);
    expect(result.decisionBasis).not.toBe('google_safe_browsing');
  });

  it('keeps unknown suspicious domains at medium caution or higher', async () => {
    const result = await performUrlScan({ url: 'https://plainordinarydomainabc.click/' });

    expect(result.riskScore).toBeGreaterThanOrEqual(36);
    expect(result.allowlisted).toBe(false);
    expect(result.riskLevel === 'MEDIUM' || result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL').toBe(true);
  });

  it('elevates heavy popup and redirect abuse even without a blacklist hit', async () => {
    const result = await performUrlScan({
      url: 'https://watchfree-redirects.example/',
      signals: {
        popupFrequency: 4,
        redirectChains: 3,
        downloadTriggers: 1,
        permissionAbuse: 1
      },
      requestContext: {
        tabCount: 9,
        timeOnPage: 2
      }
    });

    expect(result.runtimeRisk).toBeGreaterThanOrEqual(80);
    expect(result.decisionBasis).toBe('runtime_abuse_detected');
    expect(result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL').toBe(true);
  });

  it('blocks DOM-level script injection even on otherwise clean pages', async () => {
    const result = await performUrlScan({
      url: 'https://clean-looking.example/',
      signals: {
        maliciousScriptInjection: 1,
        hiddenIframes: 2,
        obfuscatedScripts: 1
      }
    });

    expect(result.domRisk).toBeGreaterThanOrEqual(50);
    expect(result.decisionBasis).toBe('malicious_script_injection_detected');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('blocks click interception and overlay traps before weighted scoring', async () => {
    const result = await performUrlScan({
      url: 'https://fake-player.example/',
      signals: {
        clickInterception: 1,
        fakePlayButtons: 2,
        invisibleOverlay: 1,
        mismatchedLinkDestinations: 1
      }
    });

    expect(result.interactionRisk).toBeGreaterThanOrEqual(40);
    expect(result.domRisk).toBeGreaterThanOrEqual(45);
    expect(result.decisionBasis === 'click_interception_detected' || result.decisionBasis === 'overlay_trap_detected').toBe(true);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('returns low-risk local context for localhost without external analysis', async () => {
    const result = await performUrlScan({ url: 'http://localhost:3000' });

    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBe(0);
    expect(result.decisionBasis).toBe('local_context');
    expect(aggregateThreatIntelMock).not.toHaveBeenCalled();
    expect(generateExplanationMock).not.toHaveBeenCalled();
  });
});
