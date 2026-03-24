import { beforeEach, vi } from 'vitest';

process.env.NODE_ENV = 'test';
process.env.PORT = '3001';
process.env.DATABASE_URL = 'postgresql://user:pass@localhost:5432/testdb';
process.env.DIRECT_URL = 'postgresql://user:pass@localhost:5432/testdb';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.ALLOWED_ORIGINS = 'http://localhost:3000,chrome-extension://test';
process.env.API_KEY = 'test-api-key';
process.env.ADMIN_KEY = 'test-admin-key';
process.env.DAILY_SALT_SECRET = '12345678901234567890123456789012';
process.env.GEMINI_TIMEOUT_MS = '1000';
process.env.GEMINI_MODEL = 'gemini-1.5-flash';
process.env.GEMINI_API_KEY = '';

const domainScore = {
  id: 'domain-1',
  domain: 'example.com',
  riskScore: 40,
  reportCount: 1,
  trustScore: 50,
  isWhitelisted: false,
  lastUpdated: new Date(),
  categories: [],
  categoryCounts: {},
  isConfirmed: false,
  scanCount: 0,
  firstSeen: new Date(),
  lastReportAt: null
};

vi.mock('../src/db/client', () => ({
  prisma: {
    $connect: vi.fn(),
    $disconnect: vi.fn(),
    $queryRaw: vi.fn().mockResolvedValue([{ '?column?': 1 }]),
    domainScore: {
      findUnique: vi.fn().mockResolvedValue(domainScore),
      findMany: vi.fn().mockResolvedValue([]),
      upsert: vi.fn().mockResolvedValue(domainScore),
      update: vi.fn().mockResolvedValue(domainScore)
    },
    detectionEvent: {
      create: vi.fn().mockResolvedValue({}),
      findMany: vi.fn().mockResolvedValue([]),
      count: vi.fn().mockResolvedValue(0),
      deleteMany: vi.fn().mockResolvedValue({})
    },
    threatReport: {
      findFirst: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue({ id: 'report-1' }),
      findMany: vi.fn().mockResolvedValue([]),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      count: vi.fn().mockResolvedValue(0)
    },
    fileScan: {
      create: vi.fn().mockResolvedValue({ id: 'file-1' }),
      count: vi.fn().mockResolvedValue(0),
      deleteMany: vi.fn().mockResolvedValue({})
    },
    downloadRecord: {
      upsert: vi.fn().mockResolvedValue({}),
      updateMany: vi.fn().mockResolvedValue({})
    },
    maliciousFile: {
      findUnique: vi.fn().mockResolvedValue(null)
    },
    appStats: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({ id: 1, totalScans: 0, totalThreats: 0, totalReports: 0, totalFileScans: 0, lastUpdated: new Date() })
    },
    rateLimitLog: {
      create: vi.fn().mockResolvedValue({}),
      deleteMany: vi.fn().mockResolvedValue({})
    },
    adminLog: {
      create: vi.fn().mockResolvedValue({})
    }
  },
  connectDatabase: vi.fn().mockResolvedValue(true),
  disconnectDatabase: vi.fn().mockResolvedValue(undefined),
  isDatabaseAvailable: vi.fn().mockReturnValue(false)
}));

beforeEach(async () => {
  vi.clearAllMocks();
  const { cacheService } = await import('../src/services/cache.service');
  await cacheService.del('health:status');
  await cacheService.del('reports:recent');
  await cacheService.del('stats:app');
});
