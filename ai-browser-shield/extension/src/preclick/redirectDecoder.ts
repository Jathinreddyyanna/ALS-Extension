const MAX_REDIRECT_HOPS = 5

const REDIRECT_PARAM_KEYS = [
  'target',
  'url',
  'goto',
  'dest',
  'destination',
  'redirect',
  'redirect_url',
  'redirecturi',
  'redirect_uri',
  'redir',
  'next',
  'continue',
  'return',
  'returnto',
  'returnurl',
  'out',
  'to',
  'u',
  'link',
  'r',
  'rm',
  'hash',
  'key',
  'data',
]

export const TRACKING_PARAM_KEYS = [
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'gclid',
  'fbclid',
  'msclkid',
  'clickid',
  'click_id',
  'clkid',
  'kwid',
  'aff_id',
  'affiliate_id',
  'aid',
  'ref',
  'referrer',
  'partner_id',
  'sid',
  'session',
  'token',
  '_t',
  'h',
  'rm',
  'target',
  'hash',
  'key',
] as const

export type RedirectIntentType =
  | 'AFFILIATE'
  | 'TRACKING'
  | 'SHORTENER'
  | 'TRAFFIC_MONETIZATION'
  | 'PHISHING_VECTOR'
  | 'STANDARD'

export interface RedirectHop {
  url: string
  hostname: string
  viaParam?: string
  decodedFrom?: 'base64' | 'url_encoded' | 'plain'
}

export interface DecodedRedirectResult {
  originalUrl: string
  finalUrl: string
  chain: RedirectHop[]
  trackingParams: string[]
  redirectParams: string[]
  intentType: RedirectIntentType
  usedBase64: boolean
  usedNestedEncoding: boolean
}

const AFFILIATE_HOSTS = [
  'clickbank.net',
  'clickbank.com',
  'cj.com',
  'shareasale.com',
  'impact.com',
  'partnerize.com',
  'rakutenmarketing.com',
]

const SHORTENER_HOSTS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'rb.gy',
  'buff.ly',
  'tiny.cc',
]

const TRAFFIC_MONETIZATION_HOSTS = [
  'adstr.net',
  'outbrain.com',
  'taboola.com',
  'mgid.com',
  'propellerads.com',
  'adcash.com',
  'zedo.com',
]

function normalizeMaybeBase64(value: string): string {
  return value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')
}

function looksLikeUrl(value: string): boolean {
  return /^https?:\/\//i.test(value)
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function isLikelyBase64(value: string): boolean {
  const normalized = normalizeMaybeBase64(value)
  if (normalized.length < 12 || normalized.length % 4 === 1) return false
  if (!/^[A-Za-z0-9+/=]+$/.test(normalized)) return false

  try {
    const decoded = atob(normalized)
    return looksLikeUrl(decoded.trim())
  } catch {
    return false
  }
}

function decodeBase64Url(value: string): string | null {
  const normalized = normalizeMaybeBase64(value)
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')

  try {
    const decoded = atob(padded).trim()
    return looksLikeUrl(decoded) ? decoded : null
  } catch {
    return null
  }
}

function decodeNestedValue(value: string): {
  value: string
  decodedFrom: RedirectHop['decodedFrom']
  usedBase64: boolean
  usedNestedEncoding: boolean
} {
  let working = value.trim()
  let usedNestedEncoding = false

  for (let index = 0; index < 3; index += 1) {
    const decoded = safeDecodeURIComponent(working)
    if (decoded === working) break
    working = decoded
    usedNestedEncoding = true
  }

  const base64Decoded = isLikelyBase64(working) ? decodeBase64Url(working) : null
  if (base64Decoded) {
    return {
      value: base64Decoded,
      decodedFrom: 'base64',
      usedBase64: true,
      usedNestedEncoding,
    }
  }

  return {
    value: working,
    decodedFrom: usedNestedEncoding ? 'url_encoded' : 'plain',
    usedBase64: false,
    usedNestedEncoding,
  }
}

function toHostname(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return ''
  }
}

function detectIntentType(chain: RedirectHop[], trackingParams: string[], usedBase64: boolean): RedirectIntentType {
  const hostnames = chain.map((hop) => hop.hostname)

  if (usedBase64) return 'PHISHING_VECTOR'
  if (hostnames.some((hostname) => TRAFFIC_MONETIZATION_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`)))) {
    return 'TRAFFIC_MONETIZATION'
  }
  if (hostnames.some((hostname) => AFFILIATE_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`)))) {
    return 'AFFILIATE'
  }
  if (hostnames.some((hostname) => SHORTENER_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`)))) {
    return 'SHORTENER'
  }
  if (trackingParams.length > 0) return 'TRACKING'
  return 'STANDARD'
}

export function decodeRedirectChain(rawUrl: string, maxHops = MAX_REDIRECT_HOPS): DecodedRedirectResult {
  const chain: RedirectHop[] = []
  const trackingParams = new Set<string>()
  const redirectParams = new Set<string>()
  const seen = new Set<string>()
  let usedBase64 = false
  let usedNestedEncoding = false
  let currentUrl = rawUrl

  for (let hop = 0; hop < maxHops; hop += 1) {
    if (!looksLikeUrl(currentUrl) || seen.has(currentUrl)) break
    seen.add(currentUrl)

    let parsed: URL
    try {
      parsed = new URL(currentUrl)
    } catch {
      break
    }

    chain.push({
      url: parsed.toString(),
      hostname: parsed.hostname.toLowerCase(),
      decodedFrom: hop === 0 ? 'plain' : chain[chain.length - 1]?.decodedFrom ?? 'plain',
    })

    for (const key of parsed.searchParams.keys()) {
      const normalizedKey = key.toLowerCase()
      if (TRACKING_PARAM_KEYS.includes(normalizedKey as (typeof TRACKING_PARAM_KEYS)[number])) {
        trackingParams.add(normalizedKey)
      }
    }

    let nextUrl: string | null = null
    let decodedFrom: RedirectHop['decodedFrom'] = 'plain'

    for (const [key, value] of parsed.searchParams.entries()) {
      const normalizedKey = key.toLowerCase()
      if (!REDIRECT_PARAM_KEYS.includes(normalizedKey)) continue

      redirectParams.add(normalizedKey)
      const decoded = decodeNestedValue(value)
      usedBase64 = usedBase64 || decoded.usedBase64
      usedNestedEncoding = usedNestedEncoding || decoded.usedNestedEncoding

      if (looksLikeUrl(decoded.value)) {
        nextUrl = decoded.value
        decodedFrom = decoded.decodedFrom
        break
      }
    }

    if (!nextUrl) break

    currentUrl = nextUrl
    chain.push({
      url: nextUrl,
      hostname: toHostname(nextUrl),
      viaParam: Array.from(redirectParams).at(-1),
      decodedFrom,
    })
  }

  const normalizedChain = chain.filter((hop, index) => index === 0 || hop.url !== chain[index - 1]?.url).slice(0, maxHops)
  const finalUrl = normalizedChain.at(-1)?.url ?? rawUrl

  return {
    originalUrl: rawUrl,
    finalUrl,
    chain: normalizedChain,
    trackingParams: Array.from(trackingParams),
    redirectParams: Array.from(redirectParams),
    intentType: detectIntentType(normalizedChain, Array.from(trackingParams), usedBase64),
    usedBase64,
    usedNestedEncoding,
  }
}
