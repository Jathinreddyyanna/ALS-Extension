import Redis from 'ioredis';
import { LRUCache } from 'lru-cache';
import { env } from '../config';
import { logger } from '../utils/logger';
import { sha256 } from '../utils/crypto';

type CacheRecord<T> = { value: T; expiresAt: number };

const memoryCache = new LRUCache<string, CacheRecord<unknown>>({ max: 500 });
let redisWarned = false;

export class CacheService {
  private readonly redis: Redis | null;

  public constructor() {
    try {
      this.redis = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
      this.redis.on('error', (error) => {
        if (!redisWarned) {
          redisWarned = true;
          logger.warn({ err: error }, 'redis unavailable, using lru fallback');
        }
      });
    } catch (error) {
      this.redis = null;
      if (!redisWarned) {
        redisWarned = true;
        logger.warn({ err: error }, 'redis initialization failed, using lru fallback');
      }
    }
  }

  public async connect(): Promise<boolean> {
    if (!this.redis) {
      return false;
    }
    try {
      if (this.redis.status !== 'ready') {
        await this.redis.connect();
      }
      return true;
    } catch {
      return false;
    }
  }

  public async get<T>(key: string): Promise<T | null> {
    if (await this.connect()) {
      try {
        const value = await this.redis!.get(key);
        return value ? JSON.parse(value) as T : null;
      } catch {
        return this.getMemory<T>(key);
      }
    }
    return this.getMemory<T>(key);
  }

  public async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    memoryCache.set(key, { value, expiresAt });
    if (await this.connect()) {
      await this.redis!.set(key, JSON.stringify(value), 'EX', ttlSeconds).catch(() => undefined);
    }
  }

  public async del(key: string): Promise<void> {
    memoryCache.delete(key);
    if (await this.connect()) {
      await this.redis!.del(key).catch(() => undefined);
    }
  }

  public async ping(): Promise<boolean> {
    if (!(await this.connect())) {
      return false;
    }
    try {
      return (await this.redis!.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  public async acquireLock(key: string, ttlMs: number): Promise<boolean> {
    const lockKey = `lock:${key}`;
    if (await this.connect()) {
      const response = await this.redis!.set(lockKey, '1', 'PX', ttlMs, 'NX').catch(() => null);
      return response === 'OK';
    }
    const existing = memoryCache.get(lockKey);
    if (existing && existing.expiresAt > Date.now()) {
      return false;
    }
    memoryCache.set(lockKey, { value: '1', expiresAt: Date.now() + ttlMs });
    return true;
  }

  public async releaseLock(key: string): Promise<void> {
    const lockKey = `lock:${key}`;
    memoryCache.delete(lockKey);
    if (await this.connect()) {
      await this.redis!.del(lockKey).catch(() => undefined);
    }
  }

  private getMemory<T>(key: string): T | null {
    const value = memoryCache.get(key);
    if (!value) {
      return null;
    }
    if (value.expiresAt < Date.now()) {
      memoryCache.delete(key);
      return null;
    }
    return value.value as T;
  }
}

export const cacheService = new CacheService();

export const cacheKeys = {
  urlScan: (url: string) => `scan:url:${sha256(url)}`,
  domain: (domain: string) => `scan:domain:${domain}`,
  health: 'health:status',
  stats: 'stats:app',
  reportsRecent: 'reports:recent',
  aiDebug: 'ai:debug'
};

export const getScanTtlSeconds = (riskScore: number, isWhitelisted: boolean, urlType: string): number => {
  if (urlType === 'localhost' || urlType === 'private_ip') {
    return 0;
  }
  if (isWhitelisted) {
    return 4 * 60 * 60;
  }
  if (riskScore >= 50) {
    return env.SCAN_CACHE_TTL_HIGH;
  }
  if (riskScore >= 30) {
    return 15 * 60;
  }
  return env.SCAN_CACHE_TTL_LOW;
};
