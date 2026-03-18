import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app';

describe('rateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('enforces per-ip limit on /scan/url', async () => {
    const app = createApp();
    for (let index = 0; index < 60; index += 1) {
      await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '1.1.1.1').send({ url: `https://example.com/${index}` });
    }
    const response = await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '1.1.1.1').send({ url: 'https://example.com/final' });
    expect(response.status).toBe(429);
  });

  it('enforces per-key limit on /scan/url', async () => {
    const app = createApp();
    for (let index = 0; index < 300; index += 1) {
      await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', `2.2.2.${index}`).send({ url: `https://example.com/${index}` });
    }
    const response = await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '3.3.3.3').send({ url: 'https://example.com/final-key' });
    expect(response.status).toBe(429);
  }, 20000);

  it('does not share limits between different ips', async () => {
    const app = createApp();
    await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '4.4.4.4').send({ url: 'https://example.com/one' });
    vi.advanceTimersByTime(60_001);
    const response = await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '5.5.5.5').send({ url: 'https://example.com/two' });
    expect(response.status).toBe(200);
  });

  it('resets after the window', async () => {
    const app = createApp();
    await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '6.6.6.6').send({ url: 'https://example.com/reset-1' });
    for (let index = 0; index < 60; index += 1) {
      await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '6.6.6.6').send({ url: `https://example.com/reset-${index + 2}` });
    }
    vi.advanceTimersByTime(60_001);
    const response = await request(app).post('/api/v1/scan/url').set('x-api-key', 'test-api-key').set('x-forwarded-for', '6.6.6.6').send({ url: 'https://example.com/reset-final' });
    expect(response.status).toBe(200);
  });
});
