type LiveSignalName =
  | 'POPUP_DETECTED'
  | 'POPUP_TRAP'
  | 'REDIRECT_BURST'
  | 'CLICKJACK_IFRAME'
  | 'POINTER_EVENTS_OVERLAY'
  | 'FAKE_LOGIN_FORM'
  | 'INSECURE_FORM_ACTION'
  | 'CRYPTO_WALLET_KEYWORDS'
  | 'PERMISSION_REQUEST_WITHOUT_USER_ACTION'
  | 'HIDDEN_IFRAME'
  | 'SUSPICIOUS_AUTOFILL_TARGET'

type LiveSignalPayload = {
  signal: LiveSignalName
  scoreIncrease: number
  url: string
  detail: string
  timestamp: number
}

const OFFICIAL_CRYPTO_DOMAINS = [
  'metamask.io',
  'ledger.com',
  'trezor.io',
  'coinbase.com',
]

const TRUSTED_DOMAIN_FAMILIES = [
  'google.com',
  'google.co.in',
  'google.co.uk',
  'amazon.com',
  'amazon.in',
  'amazon.co.uk',
  'paypal.com',
  'microsoft.com',
  'office.com',
  'outlook.com',
  'apple.com',
  'github.com',
  'linkedin.com',
  'facebook.com',
  'instagram.com',
  'youtube.com',
  'ebay.com',
  'stripe.com',
  'netflix.com',
  'openai.com',
  'chatgpt.com',
  'x.com',
  'twitter.com',
  'reddit.com',
  'shopify.com',
  'walmart.com',
  'target.com',
  'flipkart.com',
  'sbi.co.in',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'citi.com',
]

const CRYPTO_KEYWORDS = [
  'metamask',
  'ledger',
  'trezor',
  'seed phrase',
  'private key',
  'wallet connect',
  'recovery phrase',
  'connect wallet',
]

function sendLiveSignal(payload: LiveSignalPayload) {
  try {
    chrome.runtime.sendMessage({
      type: 'LIVE_SIGNAL_DETECTED',
      payload,
    }, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore extension context failures.
  }
}

function isOfficialCryptoDomain(hostname: string) {
  const clean = hostname.replace(/^www\./, '').toLowerCase()
  return OFFICIAL_CRYPTO_DOMAINS.some((domain) => clean === domain || clean.endsWith(`.${domain}`))
}

function isTrustedPopularDomain(hostname: string) {
  const clean = hostname.replace(/^www\./, '').toLowerCase()
  return TRUSTED_DOMAIN_FAMILIES.some((domain) => clean === domain || clean.endsWith(`.${domain}`))
}

function isHiddenFrame(frame: HTMLIFrameElement) {
  const rect = frame.getBoundingClientRect()
  const style = window.getComputedStyle(frame)
  return (
    rect.width === 0 ||
    rect.height === 0 ||
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    style.opacity === '0'
  )
}

export class LiveBehaviorMonitor {
  private readonly popupTimestamps: number[] = []
  private readonly redirectTimestamps: number[] = []
  private userActionWindowUntil = 0
  private reportedSignals = new Set<string>()
  private observer: MutationObserver | null = null

  start() {
    if (!location.href.startsWith('http')) return

    this.trackUserActions()
    this.monitorBeforeUnload()
    this.monitorPopups()
    this.monitorRedirects()
    this.scanHiddenIframes()
    this.scanClickjacking()
    this.scanForms()
    this.scanCryptoKeywords()
    this.monitorPermissionRequests()
    this.monitorMutations()
  }

  private shouldIgnoreNoiseSignal() {
    return isTrustedPopularDomain(window.location.hostname)
  }

  private trackUserActions() {
    const mark = () => {
      this.userActionWindowUntil = Date.now() + 1500
    }
    document.addEventListener('click', mark, true)
    document.addEventListener('keydown', mark, true)
    document.addEventListener('submit', mark, true)
  }

  private monitorBeforeUnload() {
    window.addEventListener('beforeunload', () => {
      if (this.shouldIgnoreNoiseSignal()) return
      this.report('POPUP_TRAP', 25, 'Page tried to trap the session during unload')
    })
  }

  private monitorPopups() {
    const originalOpen = window.open.bind(window)
    const wrapped: typeof window.open = (...args) => {
      if (this.shouldIgnoreNoiseSignal()) {
        try {
          return originalOpen(...args)
        } catch {
          return null
        }
      }

      const now = Date.now()
      this.popupTimestamps.push(now)
      this.report('POPUP_DETECTED', 25, 'Site attempted to open a popup window')

      const recentPopups = this.popupTimestamps.filter((value) => now - value < 5000)
      if (recentPopups.length > 2) {
        this.report('POPUP_TRAP', 40, 'Site opened multiple popups in a short time')
      }

      try {
        return originalOpen(...args)
      } catch {
        return null
      }
    }

    try {
      Object.defineProperty(window, 'open', {
        configurable: true,
        writable: true,
        value: wrapped,
      })
    } catch {
      try {
        ;(window as Window & { open: typeof window.open }).open = wrapped
      } catch {
        // Ignore hook failures.
      }
    }
  }

  private monitorRedirects() {
    const pushState = history.pushState.bind(history)
    const replaceState = history.replaceState.bind(history)

    const registerRedirect = (detail: string) => {
      if (this.shouldIgnoreNoiseSignal()) return
      const now = Date.now()
      this.redirectTimestamps.push(now)
      const recent = this.redirectTimestamps.filter((value) => now - value < 2000)
      if (recent.length >= 3) {
        this.report('REDIRECT_BURST', 35, detail)
      }
    }

    history.pushState = (...args) => {
      registerRedirect('Rapid redirect burst detected through history.pushState')
      return pushState(...args)
    }

    history.replaceState = (...args) => {
      registerRedirect('Rapid redirect burst detected through history.replaceState')
      return replaceState(...args)
    }

    window.addEventListener('message', (event: MessageEvent) => {
      if (event.source !== window || event.data?.type !== 'ABS_EARLY_REDIRECT_ATTEMPT') return
      registerRedirect('Rapid redirect burst detected through location navigation')
    })
  }

  private scanHiddenIframes() {
    if (this.shouldIgnoreNoiseSignal()) return
    const frames = Array.from(document.querySelectorAll('iframe'))
    for (const frame of frames) {
      if (isHiddenFrame(frame)) {
        this.report('HIDDEN_IFRAME', 40, 'Hidden iframe detected on the page')
        break
      }
    }
  }

  private scanClickjacking() {
    if (this.shouldIgnoreNoiseSignal()) return
    const viewportArea = window.innerWidth * window.innerHeight
    const elements = Array.from(document.querySelectorAll('iframe, div, section'))

    for (const element of elements) {
      const rect = element.getBoundingClientRect()
      if (rect.width <= 0 || rect.height <= 0) continue
      const coverage = (rect.width * rect.height) / Math.max(1, viewportArea)
      const style = window.getComputedStyle(element)

      if (element.tagName === 'IFRAME' && coverage > 0.3 && Number(style.opacity) < 0.2) {
        this.report('CLICKJACK_IFRAME', 50, 'Transparent iframe is covering a large part of the viewport')
        return
      }

      if (coverage > 0.3 && style.pointerEvents === 'none' && (style.position === 'fixed' || style.position === 'absolute')) {
        this.report('POINTER_EVENTS_OVERLAY', 50, 'Pointer-events overlay detected on top of page content')
        return
      }
    }
  }

  private scanForms() {
    const forms = Array.from(document.querySelectorAll('form'))
    const currentOrigin = window.location.origin

    for (const form of forms) {
      const passwordField = form.querySelector('input[type="password"]')
      if (!passwordField) continue

      const action = form.getAttribute('action') || window.location.href
      try {
        const actionUrl = new URL(action, window.location.href)
        if (actionUrl.origin !== currentOrigin) {
          this.report('FAKE_LOGIN_FORM', 45, 'Password form submits to a different domain')
        }
        if (actionUrl.protocol !== 'https:') {
          this.report('INSECURE_FORM_ACTION', 40, 'Password form uses a non-HTTPS action')
        }
      } catch {
        this.report('FAKE_LOGIN_FORM', 45, 'Password form has an invalid or deceptive action target')
      }
    }

    if (document.querySelector('[autocomplete="cc-number"], [autocomplete="cc-csc"]') && !isOfficialCryptoDomain(window.location.hostname)) {
      this.report('SUSPICIOUS_AUTOFILL_TARGET', 45, 'Page targets payment autofill fields on an untrusted domain')
    }
  }

  private scanCryptoKeywords() {
    if (isOfficialCryptoDomain(window.location.hostname) || !document.body) return

    const bodyText = document.body.innerText.toLowerCase()
    const matches = CRYPTO_KEYWORDS.filter((keyword) => bodyText.includes(keyword))
    if (matches.length >= 2) {
      this.report('CRYPTO_WALLET_KEYWORDS', 50, `Crypto wallet lure keywords found: ${matches.slice(0, 3).join(', ')}`)
    }
  }

  private monitorPermissionRequests() {
    const hadRecentUserAction = () => Date.now() < this.userActionWindowUntil

    try {
      if (navigator.clipboard?.readText) {
        const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard)
        navigator.clipboard.readText = async () => {
          if (!hadRecentUserAction()) {
            this.report('PERMISSION_REQUEST_WITHOUT_USER_ACTION', 30, 'Clipboard access requested without a recent user action')
          }
          return originalReadText()
        }
      }
    } catch {
      // Ignore clipboard hook failures.
    }

    try {
      if (navigator.mediaDevices?.getUserMedia) {
        const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices)
        navigator.mediaDevices.getUserMedia = async (...args) => {
          if (!hadRecentUserAction()) {
            this.report('PERMISSION_REQUEST_WITHOUT_USER_ACTION', 30, 'Camera or microphone permission requested without a recent user action')
          }
          return originalGetUserMedia(...args)
        }
      }
    } catch {
      // Ignore media hook failures.
    }

    try {
      if (typeof Notification !== 'undefined' && Notification.requestPermission) {
        const originalRequestPermission = Notification.requestPermission.bind(Notification)
        Notification.requestPermission = async (...args) => {
          if (!hadRecentUserAction()) {
            this.report('PERMISSION_REQUEST_WITHOUT_USER_ACTION', 30, 'Notification permission requested without a recent user action')
          }
          return originalRequestPermission(...args)
        }
      }
    } catch {
      // Ignore notification hook failures.
    }
  }

  private monitorMutations() {
    this.observer = new MutationObserver(() => {
      this.scanHiddenIframes()
      this.scanClickjacking()
      this.scanForms()
    })

    this.observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'src', 'action', 'autocomplete'],
    })
  }

  private report(signal: LiveSignalName, scoreIncrease: number, detail: string) {
    const dedupeKey = `${signal}:${detail}`
    if (this.reportedSignals.has(dedupeKey)) return
    this.reportedSignals.add(dedupeKey)

    sendLiveSignal({
      signal,
      scoreIncrease,
      url: window.location.href,
      detail,
      timestamp: Date.now(),
    })
  }
}
