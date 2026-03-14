import type { PageContextSnapshot } from '../types'

const KNOWN_BRANDS = [
  'google',
  'gmail',
  'classroom',
  'microsoft',
  'outlook',
  'paypal',
  'amazon',
  'apple',
  'netflix',
  'facebook',
  'instagram',
  'bank',
  'whatsapp',
]

function isHiddenElement(node: HTMLElement): boolean {
  const style = window.getComputedStyle(node)
  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    parseFloat(style.opacity || '1') < 0.1 ||
    node.hidden ||
    node.offsetWidth === 0 ||
    node.offsetHeight === 0
  )
}

function sameSiteAction(action: string): boolean {
  try {
    return new URL(action, window.location.href).origin === window.location.origin
  } catch {
    return true
  }
}

function insecureAction(action: string): boolean {
  try {
    return new URL(action, window.location.href).protocol === 'http:'
  } catch {
    return false
  }
}

function countBrandMismatch(content: string, hostname: string): number {
  const normalizedHost = hostname.toLowerCase().replace(/^www\./, '')
  return KNOWN_BRANDS.filter((brand) => {
    const mentionsBrand = content.includes(brand)
    const hostMatchesBrand = normalizedHost === `${brand}.com` || normalizedHost.endsWith(`.${brand}.com`) || normalizedHost.includes(brand)
    return mentionsBrand && !hostMatchesBrand
  }).length
}

function collectText(selector: string, limit: number): string[] {
  return Array.from(document.querySelectorAll(selector))
    .map(node => (node.textContent || '').replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .slice(0, limit)
}

export function extractPageContext(): PageContextSnapshot {
  const title = document.title.trim().slice(0, 120)
  const headings = collectText('h1, h2, h3', 6).map(text => text.slice(0, 120))
  const actionTexts = collectText('button, [role="button"], input[type="submit"], a', 8).map(text => text.slice(0, 80))
  const pageText = [title, ...headings, ...actionTexts, document.body?.innerText || ''].join(' ').toLowerCase()

  const inputs = Array.from(document.querySelectorAll('input, textarea, select'))

  const formSignals = inputs
    .map(node => {
      const input = node as HTMLInputElement
      const bits = [
        input.type,
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('autocomplete') || '',
        input.labels?.[0]?.textContent || '',
      ]
      return bits.join(' ').replace(/\s+/g, ' ').trim()
    })
    .filter(Boolean)
    .slice(0, 8)
    .map(text => text.slice(0, 120))

  const sensitiveInputs = inputs.filter(node => {
    const input = node as HTMLInputElement
    const joined = [
      input.type,
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('autocomplete') || '',
      input.labels?.[0]?.textContent || '',
    ].join(' ').toLowerCase()
    return ['password', 'passcode', 'otp', 'card', 'cvv', 'bank', 'iban', 'wallet', 'seed', 'ssn', 'aadhaar'].some(term => joined.includes(term))
  })
  const sensitiveFieldCount = sensitiveInputs.length
  const hiddenSensitiveFieldCount = sensitiveInputs.filter(node => node instanceof HTMLElement && isHiddenElement(node)).length

  const forms = Array.from(document.querySelectorAll('form'))
  const hiddenFormCount = forms.filter(form => form instanceof HTMLElement && isHiddenElement(form)).length
  const externalFormActionCount = forms.filter(form => {
    const action = (form.getAttribute('action') || '').trim()
    return action ? !sameSiteAction(action) : false
  }).length
  const insecureFormActionCount = forms.filter(form => {
    const action = (form.getAttribute('action') || '').trim()
    return action ? insecureAction(action) : false
  }).length

  const loginButtonCount = Array.from(document.querySelectorAll<HTMLElement>('button, [role="button"], a, input[type="submit"]'))
    .map(node => (node.textContent || (node as HTMLInputElement).value || '').trim().toLowerCase())
    .filter(text => /\b(log in|login|sign in|verify|continue|submit|authenticate)\b/.test(text))
    .length

  const bodyPreview = (document.body?.innerText || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 1000)

  const fixedOverlayCount = Array.from(document.querySelectorAll<HTMLElement>('div, section, aside, dialog'))
    .filter(node => {
      const style = window.getComputedStyle(node)
      return style.position === 'fixed' && parseInt(style.zIndex || '0', 10) >= 9999 && node.offsetWidth > 180 && node.offsetHeight > 120
    })
    .length

  const iframeCount = document.querySelectorAll('iframe').length
  const externalLinkCount = Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href]'))
    .filter(link => {
      try {
        return new URL(link.href, window.location.href).origin !== window.location.origin
      } catch {
        return false
      }
    })
    .length
  const newWindowHints = Array.from(document.querySelectorAll<HTMLElement>('a[target="_blank"], [onclick*="window.open" i], [onclick*="open(" i]')).length
  const metaRefreshCount = Array.from(document.querySelectorAll<HTMLMetaElement>('meta[http-equiv]'))
    .filter(meta => (meta.getAttribute('http-equiv') || '').toLowerCase() === 'refresh')
    .length
  const suspiciousScriptCount = Array.from(document.scripts).filter(script => {
    const src = (script.getAttribute('src') || '').toLowerCase()
    const inline = (script.textContent || '').toLowerCase()
    return (
      inline.includes('window.location') ||
      inline.includes('location.replace') ||
      inline.includes('document.write') ||
      inline.includes('eval(') ||
      src.includes('adservice') ||
      src.includes('tracker') ||
      src.includes('doubleclick') ||
      src.includes('popunder')
    )
  }).length
  const autoRedirectHintCount = Array.from(document.querySelectorAll<HTMLElement>('[onclick], a[href], button'))
    .filter(node => {
      const onclick = (node.getAttribute('onclick') || '').toLowerCase()
      const href = (node.getAttribute('href') || '').toLowerCase()
      return onclick.includes('location.href') || onclick.includes('window.location') || onclick.includes('location.replace') || href.startsWith('javascript:')
    })
    .length
  const brandMismatchCount = countBrandMismatch(pageText, window.location.hostname)

  return {
    title,
    headings,
    bodyPreview,
    formSignals,
    actionTexts,
    popupSignals: {
      fixedOverlayCount,
      iframeCount,
      externalLinkCount,
      newWindowHints,
    },
    pageSignals: {
      sensitiveFieldCount,
      hiddenSensitiveFieldCount,
      hiddenFormCount,
      loginButtonCount,
      externalFormActionCount,
      insecureFormActionCount,
      brandMismatchCount,
      suspiciousScriptCount,
      autoRedirectHintCount,
      metaRefreshCount,
    },
  }
}
