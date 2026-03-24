import { describe, expect, it } from 'vitest';
import { classifyContentCategory, computeBehaviorRisk, computeRuntimeRisk } from '../src/services/behaviorRisk.service';

describe('behaviorRisk.service', () => {
  it('classifies streaming sites and warns about intrusive redirects', () => {
    const category = classifyContentCategory('https://filmyzilla-watch.example/watch/movie', 'filmyzilla-watch.example');
    const result = computeBehaviorRisk({
      contentCategory: category,
      domainAgeDays: 7,
      cheapHosting: true,
      suspiciousKeywordScore: 0
    });

    expect(category).toBe('streaming');
    expect(result.behaviorRisk).toBe(50);
    expect(result.warnings).toContain('This site may contain intrusive ads and redirects');
  });

  it('escalates risky new login flows deterministically', () => {
    const category = classifyContentCategory('https://secure-login-check.example/account/verify', 'secure-login-check.example');
    const result = computeBehaviorRisk({
      contentCategory: category,
      domainAgeDays: 3,
      cheapHosting: false,
      suspiciousKeywordScore: 10
    });

    expect(category).toBe('login');
    expect(result.behaviorRisk).toBe(80);
  });

  it('adds runtime risk for abusive popups, redirects, and downloads', () => {
    const result = computeRuntimeRisk({
      signals: {
        popupFrequency: 3,
        redirectChains: 2,
        downloadTriggers: 1,
        permissionAbuse: 1
      },
      requestContext: {
        tabCount: 8,
        timeOnPage: 2
      }
    });

    expect(result.runtimeRisk).toBeGreaterThanOrEqual(70);
    expect(result.warnings).toContain('This page is generating excessive popups');
  });
});
