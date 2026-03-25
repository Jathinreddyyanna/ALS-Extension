import { toUnicode } from 'punycode/'

export interface HomographCheckResult {
  normalized: string
  changed: boolean
  riskAdded: number
}

/**
 * Normalizes a hostname through punycode decoding and reports whether the visible
 * hostname changed in a way that should add trust friction.
 *
 * @param host Raw hostname from a URL or navigation event.
 * @returns A normalized hostname plus a transparent risk flag.
 */
export function normalizeHostname(host: string): HomographCheckResult {
  try {
    const clean = host.trim().toLowerCase().replace(/\.+$/, '')
    if (!clean) {
      return { normalized: '', changed: false, riskAdded: 0 }
    }

    const normalized = toUnicode(clean)
    const changed = normalized !== clean

    return {
      normalized,
      changed,
      riskAdded: changed ? 20 : 0,
    }
  } catch {
    return {
      normalized: host.trim().toLowerCase(),
      changed: false,
      riskAdded: 0,
    }
  }
}
