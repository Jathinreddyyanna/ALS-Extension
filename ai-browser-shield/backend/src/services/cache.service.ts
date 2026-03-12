import Redis from 'ioredis'

let redis: Redis | null = null

export function getRedis(): Redis {
  if (!redis) {
    redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      enableReadyCheck: false,
    })
    redis.on('error', (err) => {
      console.error('[Redis] Connection error:', err.message)
    })
  }
  return redis
}

export async function cacheGet(key: string): Promise<string | null> {
  try { return await getRedis().get(key) }
  catch { return null }
}

export async function cacheSet(key: string, value: string, ttlSeconds: number): Promise<void> {
  try { await getRedis().setex(key, ttlSeconds, value) }
  catch {}
}

export async function cacheDel(key: string): Promise<void> {
  try { await getRedis().del(key) }
  catch {}
}

export async function cacheGetJSON<T>(key: string): Promise<T | null> {
  const raw = await cacheGet(key)
  if (!raw) return null
  try { return JSON.parse(raw) }
  catch { return null }
}

export async function cacheSetJSON(key: string, value: unknown, ttlSeconds: number): Promise<void> {
  await cacheSet(key, JSON.stringify(value), ttlSeconds)
}

// Cache key builders
export const keys = {
  urlScan: (url: string) => `url_scan:${Buffer.from(url).toString('base64').slice(0, 64)}`,
  domainScore: (domain: string) => `domain_score:${domain}`,
  threatFeed: () => 'threat_feed:recent',
  rateLimit: (ip: string, endpoint: string) => `rl:${endpoint}:${ip}`,
}
