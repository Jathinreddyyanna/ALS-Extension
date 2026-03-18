import { beforeEach, describe, expect, it, vi } from 'vitest';
import { prisma } from '../src/db/client';

const { analyzeWithGeminiMock } = vi.hoisted(() => ({
  analyzeWithGeminiMock: vi.fn()
}));

vi.mock('../src/services/ai.service', () => ({
  analyzeWithGemini: analyzeWithGeminiMock
}));

import { performUrlScan } from '../src/services/scan.service';

describe('scan.service', () => {
  beforeEach(() => {
    analyzeWithGeminiMock.mockReset();
    analyzeWithGeminiMock.mockResolvedValue({
      riskLevel: 'HIGH',
      riskScore: 80,
      confidence: 0.8,
      recommendedAction: 'warn',
      explanation: 'Suspicious URL',
      keyIndicators: ['suspiciousTLD'],
      category: 'phishing',
      categories: ['phishing'],
      verdict: 'malicious',
      threatVector: 'url_structure',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'gemini',
      aiDegraded: false,
      cached: false
    });
  });

  it('falls back safely when Gemini returns invalid JSON style fallback result', async () => {
    analyzeWithGeminiMock.mockResolvedValueOnce({
      riskLevel: 'MEDIUM',
      riskScore: 35,
      confidence: 0.45,
      recommendedAction: 'warn',
      explanation: 'Partial AI analysis',
      keyIndicators: ['suspiciousKeywords'],
      category: 'unknown',
      categories: [],
      verdict: 'suspicious',
      threatVector: 'url_structure',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'heuristic',
      aiDegraded: true,
      cached: false
    });
    const result = await performUrlScan({ url: 'https://example.com/login' });
    expect(result.source).toBe('heuristic');
    expect(result.aiDegraded).toBe(true);
    expect(result.aiSource).toBe('heuristic');
  });

  it('marks aiDegraded on 429 fallback', async () => {
    analyzeWithGeminiMock.mockResolvedValueOnce({
      riskLevel: 'MEDIUM',
      riskScore: 30,
      confidence: 0.4,
      recommendedAction: 'warn',
      explanation: 'rate limited',
      keyIndicators: ['domain_cache'],
      category: 'unknown',
      categories: [],
      verdict: 'suspicious',
      threatVector: 'domain_reputation',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'heuristic',
      aiDegraded: true,
      cached: false
    });
    const result = await performUrlScan({ url: 'https://example.com/login' });
    expect(result.aiDegraded).toBe(true);
  });

  it('returns heuristic-only on timeout fallback', async () => {
    analyzeWithGeminiMock.mockResolvedValueOnce({
      riskLevel: 'LOW',
      riskScore: 15,
      confidence: 0.45,
      recommendedAction: 'allow',
      explanation: 'timeout',
      keyIndicators: [],
      category: 'unknown',
      categories: [],
      verdict: 'safe',
      threatVector: 'url_structure',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'heuristic',
      aiDegraded: true,
      cached: false
    });
    const result = await performUrlScan({ url: 'https://example.com' });
    expect(result.source).toBe('heuristic');
  });

  it('survives domain score db failure', async () => {
    vi.mocked(prisma.domainScore.findUnique).mockRejectedValueOnce(new Error('db down'));
    const result = await performUrlScan({ url: 'https://dbfail.test/login' });
    expect(result.dbRiskScore).toBe(0);
  });

  it('calculates scoring formula as expected', async () => {
    vi.mocked(prisma.domainScore.findUnique).mockResolvedValueOnce({
      id: 'domain-1',
      domain: 'example.com',
      riskScore: 40,
      reportCount: 4,
      trustScore: 50,
      isWhitelisted: false,
      lastUpdated: new Date(),
      categories: [],
      categoryCounts: {},
      isConfirmed: false,
      scanCount: 0,
      firstSeen: new Date(),
      lastReportAt: null
    });
    analyzeWithGeminiMock.mockResolvedValueOnce({
      riskLevel: 'HIGH',
      riskScore: 80,
      confidence: 0.8,
      recommendedAction: 'warn',
      explanation: 'Suspicious URL',
      keyIndicators: ['suspiciousTLD'],
      category: 'phishing',
      categories: ['phishing'],
      verdict: 'malicious',
      threatVector: 'url_structure',
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'gemini',
      aiDegraded: false,
      cached: false
    });
    const result = await performUrlScan({ url: 'https://paypa1-login.xyz/verify-account' });
    expect(result.riskScore).toBeGreaterThan(60);
  });

  it('returns low risk for localhost and does not call Gemini', async () => {
    const result = await performUrlScan({ url: 'http://localhost:3000' });
    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBeLessThanOrEqual(10);
    expect(analyzeWithGeminiMock).not.toHaveBeenCalled();
  });
});
