const REDIRECT_THRESHOLD = 3
const RESET_GRACE_MS = 5000
const RAPID_WINDOW_MS = 2000
const RECENT_WINDOW_MS = 2 * 60 * 1000

const SUSPICIOUS_REDIRECT_PATTERNS = [
  'movierulz',
  'tamilrockers',
  '1tamilmv',
  'filmyzilla',
  '9xmovies',
  'mp4moviez',
  'katmoviehd',
  'vegamovies',
  'bolly4u',
  '123movies',
  'fmovies',
  'putlocker',
  'soap2day',
  'yts',
  'torrent',
  'crackedgames',
  'piracy',
  'free-download',
  'game-hack',
  'crack',
]

const SUSPICIOUS_REDIRECT_TLDS = ['.xyz', '.top', '.site', '.click', '.work']

type RedirectState = {
  count: number
  urls: string[]
  timestamps: number[]
  autoCount: number
  lastUpdated: number
}

export type RedirectRisk = {
  score: number
  triggers: string[]
  chainLength: number
}

export function scoreRedirect(chain: string[]): RedirectRisk {
  const normalized = chain.map((entry) => entry.toLowerCase())
  const chainLength = normalized.length
  const triggers: string[] = []
  let score = 0

  const hasSuspiciousDestination = normalized.some((url) =>
    SUSPICIOUS_REDIRECT_PATTERNS.some((pattern) => url.includes(pattern))
  )

  const hasSuspiciousTldRedirect = normalized.some((url) => {
    const host = parseHostname(url)
    return SUSPICIOUS_REDIRECT_TLDS.some((tld) => host.endsWith(tld))
  })

  if (chainLength > 3 || hasSuspiciousDestination || hasSuspiciousTldRedirect) {
    score += 40
    triggers.push('suspicious redirect chain')
  }

  return {
    score: Math.min(100, score),
    triggers,
    chainLength,
  }
}

const redirectMap = new Map<number, RedirectState>()

function parseHostname(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return ''
  }
}

function chainRisk(state: RedirectState): RedirectRisk {
  const base = scoreRedirect(state.urls)
  let score = base.score
  const triggers = [...base.triggers]

  const recentEvents = state.timestamps.filter(ts => state.lastUpdated - ts <= RAPID_WINDOW_MS)
  if (recentEvents.length >= 3) {
    score += 20
    triggers.push('rapid redirects')
  }

  // Extra weight when automatic redirects dominate the chain.
  if (state.autoCount >= 2) {
    score += 10
    triggers.push('automatic redirects')
  }

  return {
    score: Math.min(100, score),
    triggers,
    chainLength: state.count,
  }
}

export function trackRedirect(
  tabId: number,
  url: string,
  options?: { isAutomatic?: boolean }
): { exceeded: boolean; count: number; urls: string[]; risk: RedirectRisk } {
  const now = Date.now()
  const existing = redirectMap.get(tabId) || {
    count: 0,
    urls: [],
    timestamps: [],
    autoCount: 0,
    lastUpdated: now,
  }

  existing.count++
  existing.urls.push(url)
  existing.timestamps.push(now)
  existing.autoCount += options?.isAutomatic ? 1 : 0
  existing.lastUpdated = now

  // Bound memory for long sessions.
  if (existing.urls.length > 20) existing.urls = existing.urls.slice(-20)
  if (existing.timestamps.length > 20) existing.timestamps = existing.timestamps.slice(-20)

  redirectMap.set(tabId, existing)

  return {
    exceeded: existing.count > REDIRECT_THRESHOLD,
    count: existing.count,
    urls: existing.urls,
    risk: chainRisk(existing),
  }
}

export function getRedirectRiskForUrl(url: string): RedirectRisk {
  const now = Date.now()
  const hostname = parseHostname(url)

  if (!hostname) {
    return { score: 0, triggers: [], chainLength: 0 }
  }

  let best: RedirectRisk = { score: 0, triggers: [], chainLength: 0 }

  for (const state of redirectMap.values()) {
    if (now - state.lastUpdated > RECENT_WINDOW_MS) continue

    const matchesTarget = state.urls.some(entry => {
      const host = parseHostname(entry)
      return host === hostname || host.endsWith('.' + hostname) || hostname.endsWith('.' + host)
    })

    if (!matchesTarget) continue

    const risk = chainRisk(state)
    if (risk.score > best.score) best = risk
  }

  return best
}

export function resetTab(tabId: number) {
  const existing = redirectMap.get(tabId)
  if (!existing) return

  // Do not reset immediately for in-flight auto redirects.
  if (Date.now() - existing.lastUpdated < RESET_GRACE_MS) return
  redirectMap.delete(tabId)
}
