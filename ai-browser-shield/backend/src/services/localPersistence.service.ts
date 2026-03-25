import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Category, RiskLevel } from '../types/scan.types';
import { hashUrlForStorage } from '../utils/crypto';

type LocalDomainScore = {
  id: string;
  domain: string;
  riskScore: number;
  reportCount: number;
  trustScore: number;
  categories: string[];
  categoryCounts: Record<string, number>;
  isConfirmed: boolean;
  isWhitelisted: boolean;
  firstSeen: Date;
  lastReportAt: Date | null;
  lastUpdated: Date;
  scanCount: number;
};

type LocalDetectionEvent = {
  id: string;
  eventType: string;
  domain: string;
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  signals: Record<string, unknown>;
  aiExplanation?: string;
  verdict?: string;
  ipHash?: string;
  userAgent?: string;
  sessionId?: string;
  createdAt: Date;
  domainScoreId?: string;
  fileScanId?: string;
};

type LocalStore = {
  domainScores: Record<string, Omit<LocalDomainScore, 'firstSeen' | 'lastReportAt' | 'lastUpdated'> & {
    firstSeen: string;
    lastReportAt: string | null;
    lastUpdated: string;
  }>;
  detectionEvents: Array<Omit<LocalDetectionEvent, 'createdAt'> & { createdAt: string }>;
};

const STORE_PATH = join(process.cwd(), '.runtime', 'local-store.json');
let writeQueue: Promise<void> = Promise.resolve();

const emptyStore = (): LocalStore => ({
  domainScores: {},
  detectionEvents: []
});

/**
 * Removes raw URL material before writing a detection event to local disk.
 */
const redactDetectionEvent = (
  value: Omit<LocalDetectionEvent, 'id' | 'createdAt'> & { createdAt?: Date }
): Omit<LocalDetectionEvent, 'id' | 'createdAt'> & { createdAt?: Date } => ({
  ...value,
  url: hashUrlForStorage(value.url)
})

const hydrateDomainScore = (value: LocalStore['domainScores'][string]): LocalDomainScore => ({
  ...value,
  firstSeen: new Date(value.firstSeen),
  lastReportAt: value.lastReportAt ? new Date(value.lastReportAt) : null,
  lastUpdated: new Date(value.lastUpdated)
});

const dehydrateDomainScore = (value: LocalDomainScore): LocalStore['domainScores'][string] => ({
  ...value,
  firstSeen: value.firstSeen.toISOString(),
  lastReportAt: value.lastReportAt ? value.lastReportAt.toISOString() : null,
  lastUpdated: value.lastUpdated.toISOString()
});

const hydrateDetectionEvent = (value: LocalStore['detectionEvents'][number]): LocalDetectionEvent => ({
  ...value,
  createdAt: new Date(value.createdAt)
});

const dehydrateDetectionEvent = (value: LocalDetectionEvent): LocalStore['detectionEvents'][number] => ({
  ...value,
  createdAt: value.createdAt.toISOString()
});

const ensureStore = async (): Promise<LocalStore> => {
  try {
    const raw = await readFile(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<LocalStore>;
    return {
      domainScores: parsed.domainScores ?? {},
      detectionEvents: parsed.detectionEvents ?? []
    };
  } catch {
    return emptyStore();
  }
};

const saveStore = async (store: LocalStore): Promise<void> => {
  await mkdir(dirname(STORE_PATH), { recursive: true });
  await writeFile(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
};

const withStore = async <T>(updater: (store: LocalStore) => T | Promise<T>): Promise<T> => {
  const previous = writeQueue;
  let release!: () => void;
  writeQueue = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    const store = await ensureStore();
    const result = await updater(store);
    await saveStore(store);
    return result;
  } finally {
    release();
  }
};

export const localPersistence = {
  async getDomainScore(domain: string): Promise<LocalDomainScore | null> {
    const store = await ensureStore();
    const record = store.domainScores[domain];
    return record ? hydrateDomainScore(record) : null;
  },

  async upsertDomainScore(input: {
    domain: string;
    isWhitelisted?: boolean;
    trustScore?: number;
  }): Promise<LocalDomainScore> {
    return withStore(async (store) => {
      const existing = store.domainScores[input.domain];
      const now = new Date();
      const next: LocalDomainScore = existing
        ? {
          ...hydrateDomainScore(existing),
          isWhitelisted: input.isWhitelisted ?? existing.isWhitelisted,
          trustScore: input.trustScore ?? existing.trustScore,
          lastUpdated: now
        }
        : {
          id: randomUUID(),
          domain: input.domain,
          riskScore: 0,
          reportCount: 0,
          trustScore: input.trustScore ?? 50,
          categories: [],
          categoryCounts: {},
          isConfirmed: false,
          isWhitelisted: input.isWhitelisted ?? false,
          firstSeen: now,
          lastReportAt: null,
          lastUpdated: now,
          scanCount: 0
        };
      store.domainScores[input.domain] = dehydrateDomainScore(next);
      return next;
    });
  },

  async updateDomainScore(domain: string, updater: (current: LocalDomainScore) => LocalDomainScore): Promise<LocalDomainScore> {
    return withStore(async (store) => {
      const existing = store.domainScores[domain];
      const current = existing ? hydrateDomainScore(existing) : await this.upsertDomainScore({ domain });
      const next = updater({ ...current, lastUpdated: new Date() });
      store.domainScores[domain] = dehydrateDomainScore(next);
      return next;
    });
  },

  async listDetectionEvents(input: { domain?: string; limit: number }): Promise<LocalDetectionEvent[]> {
    const store = await ensureStore();
    return store.detectionEvents
      .map(hydrateDetectionEvent)
      .filter((item) => !input.domain || item.domain === input.domain)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, input.limit);
  },

  async createDetectionEvent(input: Omit<LocalDetectionEvent, 'id' | 'createdAt'> & { createdAt?: Date }): Promise<LocalDetectionEvent> {
    return withStore(async (store) => {
      const redacted = redactDetectionEvent(input);
      const next: LocalDetectionEvent = {
        ...redacted,
        id: randomUUID(),
        createdAt: redacted.createdAt ?? new Date()
      };
      store.detectionEvents.push(dehydrateDetectionEvent(next));
      return next;
    });
  },

  async getDomainTrend(domain: string) {
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
    const fourteenDaysAgo = now - 14 * 24 * 60 * 60 * 1000;
    const events = (await this.listDetectionEvents({ domain, limit: 500 }))
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    const currentEvents = events.filter((event) => event.createdAt.getTime() >= sevenDaysAgo);
    const previousEvents = events.filter((event) => event.createdAt.getTime() >= fourteenDaysAgo && event.createdAt.getTime() < sevenDaysAgo);
    const average = (items: LocalDetectionEvent[]) => items.length === 0 ? 0 : Math.round(items.reduce((sum, item) => sum + item.riskScore, 0) / items.length);
    return {
      current: average(currentEvents),
      previous: average(previousEvents),
      change: average(currentEvents) - average(previousEvents),
      points: currentEvents.map((event) => ({
        date: event.createdAt.toISOString().slice(0, 10),
        riskScore: event.riskScore
      }))
    };
  },

  async applyScanToDomain(input: {
    domain: string;
    riskScore: number;
    categories: Category[];
    eventRiskLevel: RiskLevel;
  }): Promise<LocalDomainScore> {
    return this.updateDomainScore(input.domain, (current) => {
      const categoryCounts = { ...current.categoryCounts };
      for (const category of input.categories) {
        categoryCounts[category] = (categoryCounts[category] ?? 0) + 1;
      }
      return {
        ...current,
        riskScore: Math.max(current.riskScore, input.riskScore),
        scanCount: current.scanCount + 1,
        categories: Array.from(new Set([...current.categories, ...input.categories])),
        categoryCounts,
        lastReportAt: ['HIGH', 'CRITICAL'].includes(input.eventRiskLevel) ? new Date() : current.lastReportAt,
        lastUpdated: new Date(),
        trustScore: Math.max(0, Math.min(100, current.isWhitelisted ? 95 : 100 - Math.round(Math.max(current.riskScore, input.riskScore) * 0.7)))
      };
    });
  }
};

