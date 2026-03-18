import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app';

describe('POST /scan/url', () => {
  it('returns scan result', async () => {
    const response = await request(createApp())
      .post('/api/v1/scan/url')
      .set('x-api-key', 'test-api-key')
      .send({ url: 'https://example.com/login' });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('riskScore');
  });

  it('rejects invalid url', async () => {
    const response = await request(createApp())
      .post('/api/v1/scan/url')
      .set('x-api-key', 'test-api-key')
      .send({ url: '' });

    expect(response.status).toBe(422);
  });
});
