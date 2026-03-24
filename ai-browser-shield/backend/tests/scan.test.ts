import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app';

describe('POST /scan/url', () => {
  it('rejects unauthorized scan requests', async () => {
    const response = await request(createApp())
      .post('/api/v1/scan/url')
      .send({ url: 'https://example.com/login' });

    expect(response.status).toBe(401);
  });

  it('returns scan result', async () => {
    const response = await request(createApp())
      .post('/api/v1/scan/url')
      .set('x-api-key', 'test-api-key')
      .send({ url: 'https://example.com/login' });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('riskScore');
    expect(response.body).toHaveProperty('sources');
    expect(response.body).toHaveProperty('confidenceLevel');
    expect(response.body).toHaveProperty('analysisDepth');
    expect(response.body).toHaveProperty('threatSource');
  });

  it('rejects invalid url', async () => {
    const response = await request(createApp())
      .post('/api/v1/scan/url')
      .set('x-api-key', 'test-api-key')
      .send({ url: '' });

    expect(response.status).toBe(422);
  });
});
