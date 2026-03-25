const REDIRECT_PARAMS = [
  'url',
  'q',
  'u',
  'redirect',
  'redirect_to',
  'redirectto',
  'target',
  'dest',
  'destination',
  'to',
  'go',
  'goto',
  'jump',
  'jump_to',
  'next',
  'continue',
  'return',
  'returnurl',
  'return_url',
  'redirect_url',
  'redirect_uri',
  'forward',
  'forward_url',
  'external',
  'external_url',
  'callback',
  'callback_url',
  'landing',
  'landing_url',
  'continue_url',
  'view',
  'path',
  'service'
];

const REDIRECTOR_DOMAINS = [
  'google.com',
  'googleadservices.com',
  'facebook.com',
  'linkedin.com',
  't.co',
  'bit.ly'
];

// URL shortener domains that require HTTP HEAD to resolve
const URL_SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'bitly.com',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'shorte.st',
  'tiny.cc',
  'soo.gd',
  'short.to',
  'cutt.ly',
  'rebrand.ly',
  'rb.gy',
  'shorturl.at',
  'v.gd',
  'clck.ru',
  'x.co',
  'lnkd.in',
  'youtu.be',
  't.me',
  'amzn.to',
  'amzn.eu',
  'fb.me',
  'fb.watch',
  'forms.gle',
  'g.co',
  'g.page',
  'maps.app.goo.gl',
  'on.fb.me',
  'qr.ae',
  'zpr.io',
  'snip.ly',
  'mcaf.ee',
  'mzl.la',
  'apple.co',
  'smarturl.it'
]);

const HTTP_RESOLVE_TIMEOUT_MS = 5000;
const MAX_HTTP_REDIRECTS = 5;

function tryDecodeUrlCandidate(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const attempts = [trimmed];
  let working = trimmed;
  for (let depth = 0; depth < 5; depth += 1) {
    const next = working
      .replace(/&amp;/gi, '&')
      .replace(/&colon;/gi, ':')
      .replace(/&sol;/gi, '/')
      .replace(/&#x3a;/gi, ':')
      .replace(/&#58;/gi, ':')
      .replace(/&#x2f;/gi, '/')
      .replace(/&#47;/gi, '/')
      .replace(/=([0-9A-F]{2})/gi, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
    try {
      const decoded = decodeURIComponent(next);
      if (!attempts.includes(decoded)) {
        attempts.push(decoded);
      }
      if (decoded === working) {
        break;
      }
      working = decoded;
    } catch {
      if (!attempts.includes(next)) {
        attempts.push(next);
      }
      break;
    }
  }

  for (const candidate of attempts) {
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.toString();
      }
    } catch {
      // Ignore invalid candidates.
    }
  }

  return null;
}

function getHashParams(parsed: URL): URLSearchParams | null {
  const hash = parsed.hash.replace(/^#/, '').trim();
  if (!hash) return null;

  const normalized = hash.startsWith('?')
    ? hash.slice(1)
    : hash.includes('?')
      ? hash.split('?').slice(1).join('?')
      : hash;

  if (!normalized.includes('=')) return null;
  return new URLSearchParams(normalized);
}

/**
 * Extracts the root registrable-looking domain from a URL.
 */
export function extractRootDomain(url: string): string {
  const hostname = new URL(url).hostname.toLowerCase();
  const parts = hostname.replace(/^www\./, '').split('.');
  return parts.slice(-2).join('.');
}

/**
 * Returns true when a domain acts as a known wrapper or redirector.
 */
export function isRedirector(domain: string): boolean {
  const clean = domain.replace(/^www\./, '').toLowerCase();
  return REDIRECTOR_DOMAINS.some((redirectorDomain) => clean === redirectorDomain || clean.endsWith(`.${redirectorDomain}`));
}

/**
 * Resolves the true destination URL through several layers of common redirect wrappers.
 */
export function resolveFinalUrl(rawUrl: string, maxDepth = 8): { finalUrl: string; chain: string[] } {
  let current = rawUrl;
  const chain = [rawUrl];
  const visitedUrls = new Set<string>([rawUrl]);

  for (let depth = 0; depth < maxDepth; depth += 1) {
    if (chain.length > 8 || visitedUrls.size > 8 || current.length > 2048) {
      break;
    }
    try {
      const parsed = new URL(current);
      let nextUrl: string | null = null;
      const hashParams = getHashParams(parsed);

      const sources: URLSearchParams[] = [parsed.searchParams];
      if (hashParams) {
        sources.push(hashParams);
      }

      for (const source of sources) {
        for (const param of REDIRECT_PARAMS) {
          const candidate = source.get(param);
          if (!candidate) continue;

          const decoded = tryDecodeUrlCandidate(candidate);
          if (decoded) {
            nextUrl = decoded;
            break;
          }
        }

        if (nextUrl) break;
      }

      if (!nextUrl && parsed.hash) {
        nextUrl = tryDecodeUrlCandidate(parsed.hash.replace(/^#/, ''));
      }

      if (!nextUrl || nextUrl === current || visitedUrls.has(nextUrl)) {
        break;
      }

      current = nextUrl;
      chain.push(nextUrl);
      visitedUrls.add(nextUrl);
    } catch {
      break;
    }
  }

  return {
    finalUrl: current,
    chain
  };
}

/**
 * Produces one canonical URL analysis object for risk and trust decisions.
 */
export function analyzeResolvedUrl(rawUrl: string) {
  const { finalUrl, chain } = resolveFinalUrl(rawUrl);
  const domain = extractRootDomain(finalUrl);

  return {
    rawUrl,
    finalUrl,
    domain,
    redirectChain: chain,
    redirector: isRedirector(extractRootDomain(rawUrl))
  };
}

/**
 * Check if a domain is a known URL shortener that requires HTTP resolution.
 */
export function isUrlShortener(domain: string): boolean {
  const clean = domain.replace(/^www\./, '').toLowerCase();
  return URL_SHORTENER_DOMAINS.has(clean);
}

/**
 * Resolve URL shorteners by following HTTP redirects.
 * Uses HEAD requests with manual redirect following for safety.
 * Returns the final destination URL and the redirect chain.
 */
export async function resolveShortUrl(shortUrl: string): Promise<{
  finalUrl: string;
  chain: string[];
  resolved: boolean;
  error?: string;
}> {
  const chain: string[] = [shortUrl];

  try {
    // Check if this is actually a URL shortener
    const hostname = new URL(shortUrl).hostname.toLowerCase();
    if (!isUrlShortener(hostname)) {
      return { finalUrl: shortUrl, chain, resolved: false };
    }

    let currentUrl = shortUrl;
    const visitedUrls = new Set<string>([shortUrl]);

    for (let i = 0; i < MAX_HTTP_REDIRECTS; i++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), HTTP_RESOLVE_TIMEOUT_MS);

        const response = await fetch(currentUrl, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
          }
        });

        clearTimeout(timeoutId);

        // Check for redirect status codes
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('location');
          if (!location) break;

          // Handle relative URLs
          let nextUrl: string;
          try {
            nextUrl = new URL(location, currentUrl).toString();
          } catch {
            break;
          }

          // Prevent loops
          if (visitedUrls.has(nextUrl)) break;

          visitedUrls.add(nextUrl);
          chain.push(nextUrl);
          currentUrl = nextUrl;

          // If we've left the shortener domain, check if we hit another shortener
          const nextHostname = new URL(nextUrl).hostname.toLowerCase();
          if (!isUrlShortener(nextHostname)) {
            // Final destination reached
            return { finalUrl: currentUrl, chain, resolved: true };
          }
        } else {
          // Not a redirect - this is the final URL
          return { finalUrl: currentUrl, chain, resolved: chain.length > 1 };
        }
      } catch (fetchError) {
        // Network error - try parameter-based resolution as fallback
        const { finalUrl: paramResolved, chain: paramChain } = resolveFinalUrl(currentUrl);
        if (paramResolved !== currentUrl) {
          chain.push(...paramChain.slice(1));
          return { finalUrl: paramResolved, chain, resolved: true };
        }
        return {
          finalUrl: currentUrl,
          chain,
          resolved: chain.length > 1,
          error: fetchError instanceof Error ? fetchError.message : 'Network error'
        };
      }
    }

    return { finalUrl: currentUrl, chain, resolved: chain.length > 1 };
  } catch (parseError) {
    return {
      finalUrl: shortUrl,
      chain,
      resolved: false,
      error: parseError instanceof Error ? parseError.message : 'Invalid URL'
    };
  }
}

/**
 * Hybrid URL resolution: first tries parameter-based resolution,
 * then HTTP-based resolution for URL shorteners.
 */
export async function resolveUrlDeep(rawUrl: string): Promise<{
  finalUrl: string;
  chain: string[];
  wasShortener: boolean;
  wasParameterRedirect: boolean;
}> {
  // Step 1: Parameter-based resolution (google.com/url?q=, etc.)
  const { finalUrl: paramResolved, chain: paramChain } = resolveFinalUrl(rawUrl);
  const wasParameterRedirect = paramChain.length > 1;

  // Step 2: Check if the resolved URL is a shortener and resolve it
  try {
    const hostname = new URL(paramResolved).hostname.toLowerCase();
    if (isUrlShortener(hostname)) {
      const shortResult = await resolveShortUrl(paramResolved);
      return {
        finalUrl: shortResult.finalUrl,
        chain: [...paramChain.slice(0, -1), ...shortResult.chain],
        wasShortener: shortResult.resolved,
        wasParameterRedirect
      };
    }
  } catch {
    // Invalid URL - return as-is
  }

  return {
    finalUrl: paramResolved,
    chain: paramChain,
    wasShortener: false,
    wasParameterRedirect
  };
}
