type RedirectState = {
  count: number;
  urls: string[];
  firstSeen: number;
  lastUpdated: number;
};

type NewTabState = {
  openerTabId: number;
  url: string;
  ts: number;
};

const redirectMap = new Map<number, RedirectState>();
const newTabMap = new Map<number, NewTabState>();

const REDIRECT_THRESHOLD = 2;
const RESET_GRACE_MS = 1_500;
const NEW_TAB_SPAM_WINDOW_MS = 3_000;
const RETURN_REDIRECT_WINDOW_MS = 5_000;

export function trackRedirect(tabId: number, url: string): {
  exceeded: boolean;
  count: number;
  urls: string[];
} {
  const now = Date.now();
  const previous = redirectMap.get(tabId);
  const existing: RedirectState = {
    count: typeof previous?.count === 'number' ? previous.count : 0,
    urls: Array.isArray(previous?.urls) ? [...previous.urls] : [],
    firstSeen: typeof previous?.firstSeen === 'number' ? previous.firstSeen : now,
    lastUpdated: typeof previous?.lastUpdated === 'number' ? previous.lastUpdated : now
  };

  existing.count += 1;
  existing.urls.push(url);
  existing.lastUpdated = now;

  if (existing.urls.length > 20) {
    existing.urls = existing.urls.slice(-20);
  }

  redirectMap.set(tabId, existing);

  return {
    exceeded: existing.count > REDIRECT_THRESHOLD,
    count: existing.count,
    urls: [...existing.urls]
  };
}

export function trackNewTab(newTabId: number, openerTabId: number, url: string): void {
  newTabMap.set(newTabId, { openerTabId, url, ts: Date.now() });
}

export function getNewTabInfo(tabId: number): NewTabState | null {
  return newTabMap.get(tabId) ?? null;
}

export function clearNewTabInfo(tabId: number): void {
  newTabMap.delete(tabId);
}

export function resetTab(tabId: number): void {
  const existing = redirectMap.get(tabId);
  if (existing && Date.now() - existing.lastUpdated < RESET_GRACE_MS) {
    return;
  }

  redirectMap.delete(tabId);
  newTabMap.delete(tabId);
}

export const REDIRECT_THRESHOLD_VALUE = REDIRECT_THRESHOLD;
export const NEW_TAB_SPAM_WINDOW = NEW_TAB_SPAM_WINDOW_MS;
export const RETURN_REDIRECT_WINDOW = RETURN_REDIRECT_WINDOW_MS;
