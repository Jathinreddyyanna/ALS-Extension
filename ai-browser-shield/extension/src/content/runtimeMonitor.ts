/**
 * Boots the isolated runtime monitor for the active page.
 */
export function initRuntimeMonitor() {
  // PHASE 3: initialize the isolated runtime protection engine once per page
  if ((window as Window & { __absRuntimeMonitorInitialized?: boolean }).__absRuntimeMonitorInitialized) {
    return
  }

  ;(window as Window & { __absRuntimeMonitorInitialized?: boolean }).__absRuntimeMonitorInitialized = true

  ;(() => {
    // PHASE 3: skip extension, local development, and non-http pages entirely
    if (!location.href.startsWith('http')) return

    const hostname = window.location.hostname.toLowerCase()
    if (
      location.href.startsWith('chrome://') ||
      location.href.startsWith('chrome-extension://') ||
      location.href.startsWith('about://') ||
      location.href.startsWith('file://') ||
      hostname === 'localhost' ||
      hostname === '127.0.0.1'
    ) {
      return
    }

    const params = new URLSearchParams(window.location.search)
    if (params.get('abs_runtime_bypass') === '1') {
      return
    }

    const runtimeState = {
      popupCount: 0,
      redirectCount: 0,
      hiddenIframeCount: 0,
      domMutationCount: 0,
      overlayCount: 0,
      scriptInjectionCount: 0,
      suspiciousFormCount: 0,
      passwordFieldCount: 0,
      creditCardFieldCount: 0,
      autoSubmitCount: 0,
      earlyUnloadCount: 0,
      jsRedirectCount: 0,
      metaRefreshCount: 0,
      runtimeScore: 0,
      startTime: Date.now(),
      blocked: false,
      warned: false,
    }

    const WEIGHTS = {
      popup: 10,
      redirect: 15,
      hiddenIframe: 25,
      suspiciousForm: 30,
      scriptInjection: 20,
      overlay: 25,
      earlyUnload: 18,
      passwordField: 12,
      creditCardField: 16,
      jsRedirect: 18,
      metaRefresh: 18,
    } as const

    // PHASE 3: use a fixed phishing phrase list for one-time intent scanning
    const PHISHING_KEYWORDS = [
      'verify your account',
      'confirm your identity',
      'unusual activity',
      'suspended',
      'limited access',
      'update your information',
      'your account will be closed',
      'click here to restore',
      'enter your password',
      're-enter your credentials',
      'download required',
      'install update',
      'your device is infected',
      'you have won',
      'claim your prize',
      'wire transfer',
    ] as const

    const SIGNAL_FLUSH_DEBOUNCE_MS = 900
    const SIGNAL_FLUSH_INTERVAL_MS = 6000
    const MONITORING_INTERVAL_MS = 3000
    const NOTIFICATION_COOLDOWN_MS = 15000
    let lastBackgroundSendAt = 0
    let lastNotificationAt = 0
    let signalFlushTimer: number | null = null
    let phishingScanComplete = false
    let metaRefreshDetected = false
    let inlineJsRedirectDetected = false
    const PAGE_EVENT_TYPE = 'ABS_PAGE_DANGEROUS_API'

    // PHASE 3: centralize score updates and cap runtime risk at 100
    function addScore(points: number) {
      runtimeState.runtimeScore = Math.min(100, runtimeState.runtimeScore + points)
    }

    /**
     * Returns true when the current page looks like a sensitive workflow.
     */
    function isSensitivePath() {
      return /login|signin|auth|account|verify|secure|checkout|payment|billing|wallet/i.test(
        `${window.location.pathname} ${document.title}`
      )
    }

    /**
     * Recomputes runtime risk from the current signal bundle.
     */
    function applyAdaptiveRisk() {
      let score = 0

      score += runtimeState.popupCount * WEIGHTS.popup
      score += runtimeState.redirectCount * WEIGHTS.redirect
      score += runtimeState.hiddenIframeCount * WEIGHTS.hiddenIframe
      score += runtimeState.overlayCount * WEIGHTS.overlay
      score += runtimeState.scriptInjectionCount * WEIGHTS.scriptInjection
      score += runtimeState.suspiciousFormCount * WEIGHTS.suspiciousForm
      score += runtimeState.earlyUnloadCount * WEIGHTS.earlyUnload
      score += runtimeState.jsRedirectCount * WEIGHTS.jsRedirect
      score += runtimeState.metaRefreshCount * WEIGHTS.metaRefresh

      const onSensitivePath = isSensitivePath()
      if (runtimeState.passwordFieldCount > 0) {
        score += runtimeState.passwordFieldCount * (onSensitivePath ? 4 : WEIGHTS.passwordField)
      }
      if (runtimeState.creditCardFieldCount > 0) {
        score += runtimeState.creditCardFieldCount * (onSensitivePath ? 6 : WEIGHTS.creditCardField)
      }

      if (onSensitivePath && runtimeState.hiddenIframeCount > 0) {
        score += 40
      }

      if (runtimeState.popupCount > 2 && runtimeState.hiddenIframeCount > 0 && runtimeState.suspiciousFormCount > 0) {
        score += 50
      }

      if (runtimeState.redirectCount > 1 && runtimeState.earlyUnloadCount > 0) {
        score += 35
      }

      runtimeState.runtimeScore = Math.min(100, Math.max(runtimeState.runtimeScore, score))
    }

    // PHASE 3: compute the current runtime risk level from the single state object
    function getRuntimeRiskLevel(): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
      const score = runtimeState.runtimeScore
      if (score >= 70) return 'CRITICAL'
      if (score >= 50) return 'HIGH'
      if (score >= 30) return 'MEDIUM'
      return 'LOW'
    }

    // PHASE 3: safely send runtime telemetry to the background worker
    function sendSignalsToBackground() {
      try {
        chrome.runtime.sendMessage({
          type: 'RUNTIME_SIGNALS_UPDATE',
          payload: {
            url: window.location.href,
            runtimeScore: runtimeState.runtimeScore,
            riskLevel: getRuntimeRiskLevel(),
            signals: {
              popupCount: runtimeState.popupCount,
              popupFrequency: runtimeState.popupCount,
              redirectCount: runtimeState.redirectCount,
              redirectChains: runtimeState.redirectCount,
              hiddenIframeCount: runtimeState.hiddenIframeCount,
              hiddenIframes: runtimeState.hiddenIframeCount,
              overlayCount: runtimeState.overlayCount,
              overlayTrap: runtimeState.overlayCount,
              scriptInjectionCount: runtimeState.scriptInjectionCount,
              suspiciousFormCount: runtimeState.suspiciousFormCount,
              domMutationCount: runtimeState.domMutationCount,
              passwordFieldCount: runtimeState.passwordFieldCount,
              creditCardFieldCount: runtimeState.creditCardFieldCount,
              earlyUnloadCount: runtimeState.earlyUnloadCount,
              jsRedirectCount: runtimeState.jsRedirectCount,
              metaRefreshCount: runtimeState.metaRefreshCount,
            },
          },
        }, () => {
          void chrome.runtime.lastError
        })
      } catch {
        // Extension context may be invalidated — silently ignore.
      }
    }

    /**
     * Debounces background updates during noisy mutation bursts.
     */
    function scheduleSignalsToBackground() {
      if (signalFlushTimer !== null) {
        window.clearTimeout(signalFlushTimer)
      }
      signalFlushTimer = window.setTimeout(() => {
        signalFlushTimer = null
        lastBackgroundSendAt = Date.now()
        sendSignalsToBackground()
      }, SIGNAL_FLUSH_DEBOUNCE_MS)
    }

    function reportDangerousApiCall(kind: string, target: string) {
      try {
        chrome.runtime.sendMessage({
          type: 'DANGEROUS_API_CALL',
          payload: {
            kind,
            target,
            url: window.location.href,
            timestamp: Date.now(),
          },
        }, () => {
          void chrome.runtime.lastError
        })
      } catch {
        // Ignore extension messaging failures.
      }
    }

    /**
     * Returns true when inline script content looks like a client-side redirect.
     */
    function looksLikeJsRedirect(source: string) {
      return /(window\.location|location\.(assign|replace|href)|top\.location|document\.location)\s*(=|\()/.test(source)
    }

    /**
     * Records a suspicious redirect-style signal and updates runtime risk.
     */
    function recordRedirectStyleSignal(kind: 'js' | 'meta') {
      if (kind === 'js') {
        if (inlineJsRedirectDetected) return
        inlineJsRedirectDetected = true
        runtimeState.jsRedirectCount += 1
        runtimeState.redirectCount += 1
        addScore(WEIGHTS.jsRedirect)
      } else {
        if (metaRefreshDetected) return
        metaRefreshDetected = true
        runtimeState.metaRefreshCount += 1
        runtimeState.redirectCount += 1
        addScore(WEIGHTS.metaRefresh)
      }
      reportDangerousApiCall(kind === 'js' ? 'js_redirect' : 'meta_refresh', window.location.href)
      applyAdaptiveRisk()
      scheduleSignalsToBackground()
    }

    /**
     * Detects meta refresh redirects on initial load and during DOM mutation.
     */
    function inspectMetaRefresh(root: ParentNode) {
      const metaRefreshNodes = root.querySelectorAll?.('meta[http-equiv]') ?? []
      for (const node of metaRefreshNodes) {
        const meta = node as HTMLMetaElement
        if (meta.httpEquiv.toLowerCase() !== 'refresh') continue
        const content = meta.content || ''
        const parts = content.split(';')
        const destination = parts.find((part) => /url\s*=/i.test(part))
        if (!destination) continue
        recordRedirectStyleSignal('meta')
        break
      }
    }

    /**
     * Detects inline event handlers that attempt client-side navigation.
     */
    function inspectInlineRedirectHandlers(root: ParentNode) {
      const selector = '[onclick],[onload],[onerror],[onsubmit]'
      const candidates = root.querySelectorAll?.(selector) ?? []
      for (const node of candidates) {
        const element = node as Element
        const script =
          element.getAttribute('onclick') ??
          element.getAttribute('onload') ??
          element.getAttribute('onerror') ??
          element.getAttribute('onsubmit') ??
          ''

        if (!script) continue
        if (looksLikeJsRedirect(script)) {
          recordRedirectStyleSignal('js')
          break
        }
      }
    }

    /**
     * Hooks page-context APIs that can trigger redirect or code-execution flows.
     */
    function hookDangerousApis() {
      window.addEventListener('message', (event: MessageEvent) => {
        if (event.source !== window || !event.data || event.data.type !== PAGE_EVENT_TYPE) return
        const payload = event.data.payload as { kind?: string; value?: string } | undefined
        if (!payload?.kind) return

        if (payload.kind === 'eval_redirect' || payload.kind === 'function_redirect') {
          recordRedirectStyleSignal('js')
        } else if (payload.kind === 'window_open') {
          runtimeState.popupCount += 1
          reportDangerousApiCall(payload.kind, payload.value ?? '')
          applyAdaptiveRisk()
          scheduleSignalsToBackground()
        }
      })

      try {
        const script = document.createElement('script')
        script.src = chrome.runtime.getURL('dangerousApiInjected.js')
        script.setAttribute('data-shield-injected', '1')
        script.async = false
        script.onload = () => script.remove()
        script.onerror = () => script.remove()
        ;(document.head || document.documentElement).appendChild(script)
      } catch {
        // Ignore page-context hook failures.
      }
    }

    // PHASE 3: show a single non-blocking runtime warning banner
    function showWarningBanner() {
      if (document.getElementById('abs-warning-banner')) return
      if (Date.now() - lastNotificationAt < NOTIFICATION_COOLDOWN_MS) return
      lastNotificationAt = Date.now()

      const banner = document.createElement('div')
      banner.id = 'abs-warning-banner'
      Object.assign(banner.style, {
        position: 'fixed',
        top: '0',
        left: '0',
        width: '100%',
        zIndex: '2147483647',
        background: '#f59e0b',
        color: '#111827',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        padding: '12px 16px',
        fontFamily: 'system-ui, sans-serif',
        fontSize: '14px',
        fontWeight: '600',
        boxSizing: 'border-box',
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      })

      const textWrap = document.createElement('div')
      textWrap.style.flex = '1'

      const line = document.createElement('div')
      line.textContent =
        '⚠️ AI Browser Shield detected suspicious behavior on this page. Popups, redirects, or hidden content were detected.'
      textWrap.appendChild(line)

      const actions = document.createElement('div')
      actions.style.display = 'flex'
      actions.style.gap = '8px'
      actions.style.flexShrink = '0'

      const dismissButton = document.createElement('button')
      dismissButton.textContent = 'Dismiss'
      Object.assign(dismissButton.style, {
        background: '#111827',
        color: '#f9fafb',
        border: 'none',
        borderRadius: '8px',
        padding: '8px 12px',
        cursor: 'pointer',
        fontSize: '13px',
      })
      dismissButton.addEventListener('click', () => {
        runtimeState.warned = true
        banner.remove()
      })

      const learnMoreButton = document.createElement('button')
      learnMoreButton.textContent = 'View Details'
      Object.assign(learnMoreButton.style, {
        background: '#fef3c7',
        color: '#111827',
        border: '1px solid rgba(17,24,39,0.15)',
        borderRadius: '8px',
        padding: '8px 12px',
        cursor: 'pointer',
        fontSize: '13px',
      })
      learnMoreButton.addEventListener('click', () => {
        try {
          chrome.runtime.sendMessage({ type: 'OPEN_POPUP' }, () => {
            void chrome.runtime.lastError
          })
        } catch {
          // Ignore popup launch failures.
        }
      })

      actions.append(dismissButton, learnMoreButton)
      banner.append(textWrap, actions)
      document.documentElement.appendChild(banner)
    }

    // PHASE 3: replace the malicious page with a blocking interstitial at critical risk
    function showBlockPage() {
      const score = runtimeState.runtimeScore
      const popupText = `${runtimeState.popupCount}`
      const redirectText = `${runtimeState.redirectCount}`
      const hiddenIframeText = runtimeState.hiddenIframeCount > 0 ? 'Yes' : 'No'
      const suspiciousFormText = runtimeState.suspiciousFormCount > 0 ? 'Yes' : 'No'

      document.documentElement.innerHTML = `
        <head>
          <title>AI Browser Shield Runtime Block</title>
        </head>
        <body style="margin:0;background:#1a1a2e;color:#f8fafc;font-family:system-ui,sans-serif;">
          <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px;box-sizing:border-box;">
            <div style="max-width:720px;width:100%;background:rgba(15,23,42,0.92);border:1px solid rgba(248,250,252,0.1);border-radius:18px;padding:32px;box-shadow:0 24px 60px rgba(0,0,0,0.45);">
              <div style="font-size:30px;font-weight:800;margin-bottom:12px;">AI Browser Shield blocked this page</div>
              <div style="font-size:16px;line-height:1.6;color:#cbd5e1;margin-bottom:24px;">
                This page showed multiple high-risk behaviors and was paused to protect your session.
              </div>
              <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px;">
                <div style="background:#111827;border-radius:12px;padding:14px;">
                  <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;">Popups detected</div>
                  <div style="font-size:24px;font-weight:700;">${popupText}</div>
                </div>
                <div style="background:#111827;border-radius:12px;padding:14px;">
                  <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;">Redirects detected</div>
                  <div style="font-size:24px;font-weight:700;">${redirectText}</div>
                </div>
                <div style="background:#111827;border-radius:12px;padding:14px;">
                  <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;">Hidden iframes</div>
                  <div style="font-size:24px;font-weight:700;">${hiddenIframeText}</div>
                </div>
                <div style="background:#111827;border-radius:12px;padding:14px;">
                  <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;">Suspicious forms</div>
                  <div style="font-size:24px;font-weight:700;">${suspiciousFormText}</div>
                </div>
              </div>
              <div style="background:#111827;border-radius:12px;padding:16px;margin-bottom:24px;">
                <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;">Runtime risk score</div>
                <div style="font-size:32px;font-weight:800;">${score} / 100</div>
              </div>
              <div style="display:flex;gap:12px;flex-wrap:wrap;">
                <button id="abs-runtime-go-back" style="background:#2563eb;color:#fff;border:none;border-radius:10px;padding:12px 18px;font-size:14px;font-weight:700;cursor:pointer;">
                  Go Back
                </button>
                <button id="abs-runtime-continue" style="background:transparent;color:#cbd5e1;border:1px solid rgba(203,213,225,0.35);border-radius:10px;padding:12px 18px;font-size:14px;font-weight:700;cursor:pointer;">
                  Continue for this session
                </button>
              </div>
            </div>
          </div>
        </body>
      `

      document.getElementById('abs-runtime-go-back')?.addEventListener('click', () => {
        history.back()
      })

      document.getElementById('abs-runtime-continue')?.addEventListener('click', () => {
        runtimeState.blocked = false
        const url = new URL(window.location.href)
        url.searchParams.set('abs_runtime_bypass', '1')
        window.location.replace(url.toString())
      })
    }

    // PHASE 3: count popup attempts while preserving the original window.open behavior
    function hookWindowOpen() {
      const _originalOpen = window.open.bind(window)

      const wrappedOpen: typeof window.open = function (...args) {
        try {
          runtimeState.popupCount += 1
          applyAdaptiveRisk()
          scheduleSignalsToBackground()
        } catch {
        // Ignore scoring failures and still call the original API.
        }

        try {
          return _originalOpen(...args)
        } catch {
          return null
        }
      }

      try {
        Object.defineProperty(window, 'open', {
          writable: false,
          configurable: false,
          value: wrappedOpen,
        })
      } catch {
        try {
          ;(window as Window & { open: typeof window.open }).open = wrappedOpen
        } catch {
          // Ignore hook hardening failures.
        }
      }
    }

    // PHASE 3: track history-based redirects and early unload escapes
    function hookNavigation() {
      const _originalPushState = history.pushState.bind(history)
      const _originalReplaceState = history.replaceState.bind(history)

      const countRedirect = () => {
        runtimeState.redirectCount += 1
        applyAdaptiveRisk()
        scheduleSignalsToBackground()
      }

      history.pushState = function (...args: Parameters<History['pushState']>) {
        countRedirect()
        return _originalPushState(...args)
      }

      history.replaceState = function (...args: Parameters<History['replaceState']>) {
        countRedirect()
        return _originalReplaceState(...args)
      }

      window.addEventListener('beforeunload', () => {
        if (Date.now() - runtimeState.startTime < 3000) {
          runtimeState.earlyUnloadCount += 1
          applyAdaptiveRisk()
          scheduleSignalsToBackground()
        }
      })
    }

    /**
     * Counts password and payment fields within the provided subtree.
     */
    function scanSensitiveInputs(root: ParentNode) {
      const passwordInputs = root.querySelectorAll?.('input[type="password"]') ?? []
      if (passwordInputs.length > 0) {
        runtimeState.passwordFieldCount = Math.max(runtimeState.passwordFieldCount, passwordInputs.length)
        const onLoginPath = /login|signin|auth|account|verify|secure/i.test(window.location.pathname)
        if (!onLoginPath) {
          runtimeState.suspiciousFormCount = Math.max(runtimeState.suspiciousFormCount, passwordInputs.length)
        }
      }

      const cardInputs = root.querySelectorAll?.(
        'input[autocomplete="cc-number"], input[name*="card" i], input[id*="card" i], input[placeholder*="card" i]'
      ) ?? []
      if (cardInputs.length > 0) {
        runtimeState.creditCardFieldCount = Math.max(runtimeState.creditCardFieldCount, cardInputs.length)
      }
      inspectMetaRefresh(root)
      inspectInlineRedirectHandlers(root)
      scheduleSignalsToBackground()
    }

    // PHASE 3: process mutation targets outside the observer callback to keep it lightweight
    function processAddedElement(element: Element) {
      if (runtimeState.blocked) return

      try {
        const tagName = element.tagName

        if (tagName === 'IFRAME') {
          runtimeState.hiddenIframeCount += 1
          const iframe = element as HTMLIFrameElement
          const rect = iframe.getBoundingClientRect()
          const style = window.getComputedStyle(iframe)
          const isHidden =
            rect.width === 0 ||
            rect.height === 0 ||
            style.opacity === '0' ||
            style.display === 'none' ||
            style.visibility === 'hidden'

          if (!isHidden) {
            runtimeState.hiddenIframeCount = Math.max(0, runtimeState.hiddenIframeCount - 1)
          }
          applyAdaptiveRisk()
        }

        if (tagName === 'SCRIPT' && Date.now() - runtimeState.startTime > 2000) {
          runtimeState.scriptInjectionCount += 1
          const script = element as HTMLScriptElement
          if (!script.src && looksLikeJsRedirect(script.textContent ?? '')) {
            recordRedirectStyleSignal('js')
          }
          if (script.src) {
            const isExternal = (() => {
              try {
                return new URL(script.src, window.location.href).origin !== window.location.origin
              } catch {
                return true
              }
            })()
            addScore(isExternal ? 10 : 0)
          } else {
            addScore(5)
          }
          applyAdaptiveRisk()
        }

        const style = window.getComputedStyle(element)
        const rect = (element as HTMLElement).getBoundingClientRect()
        const zIndex = Number.parseInt(style.zIndex || '0', 10)
        const isOverlay =
          (style.position === 'fixed' || style.position === 'absolute') &&
          zIndex > 999 &&
          rect.width > window.innerWidth * 0.75 &&
          rect.height > window.innerHeight * 0.75

        if (isOverlay) {
          runtimeState.overlayCount += 1
          applyAdaptiveRisk()
        }

        const isLoginPath = /login|signin|auth|account|verify|secure/i.test(window.location.pathname)
        const hasPasswordInput =
          tagName === 'FORM'
            ? (element as HTMLFormElement).querySelector('input[type="password"]') !== null
            : element.matches('input[type="password"]') || element.querySelector('input[type="password"]') !== null

        if ((tagName === 'FORM' || hasPasswordInput) && !isLoginPath) {
          runtimeState.suspiciousFormCount += 1
          applyAdaptiveRisk()
        }

        if (tagName === 'FORM') {
          const form = element as HTMLFormElement
          const onsubmit = form.getAttribute('onsubmit') ?? ''
          if (onsubmit.includes('submit()') || onsubmit.includes('auto')) {
            runtimeState.autoSubmitCount += 1
          }
        }

        if (tagName === 'META') {
          inspectMetaRefresh(element.parentElement ?? document)
        }

        scanSensitiveInputs(element)
        applyAdaptiveRisk()
        scheduleSignalsToBackground()
      } catch {
        // Ignore individual node inspection failures.
      }
    }

    // PHASE 3: watch the live DOM for injected iframes, scripts, overlays, and forms
    function startMutationObserver() {
      const attachObserver = () => {
        if (!document.body) return

        const observer = new MutationObserver((mutations) => {
          const elementsToProcess: Element[] = []

          for (const mutation of mutations) {
            runtimeState.domMutationCount += mutation.addedNodes.length
            for (const node of mutation.addedNodes) {
              if (node.nodeType === Node.ELEMENT_NODE) {
                elementsToProcess.push(node as Element)
              }
            }
          }

          if (elementsToProcess.length > 0) {
            window.setTimeout(() => {
              for (const element of elementsToProcess) {
                processAddedElement(element)
              }
              applyAdaptiveRisk()
            }, 0)
          }
        })

        observer.observe(document.body, {
          childList: true,
          subtree: true,
        })
      }

      if (document.body) {
        attachObserver()
        return
      }

      document.addEventListener('DOMContentLoaded', attachObserver, { once: true })
    }

    // PHASE 3: run one deferred phishing text scan after the page settles
    function schedulePhishingTextScan() {
      const runScan = () => {
        window.setTimeout(() => {
          if (phishingScanComplete || !document.body) return
          phishingScanComplete = true

          try {
            const text = document.body.innerText.toLowerCase()
            let scoreContribution = 0

            for (const keyword of PHISHING_KEYWORDS) {
              if (text.includes(keyword)) {
                scoreContribution += 8
              }
            }

            if (scoreContribution > 0) {
              addScore(Math.min(30, scoreContribution))
              applyAdaptiveRisk()
              scheduleSignalsToBackground()
            }
          } catch {
            // Ignore text scan failures.
          }
        }, 1500)
      }

      if (document.readyState === 'complete') {
        runScan()
        return
      }

      window.addEventListener('load', runScan, { once: true })
    }

    hookWindowOpen()
    hookNavigation()
    hookDangerousApis()
    startMutationObserver()
    schedulePhishingTextScan()
    scanSensitiveInputs(document)
    applyAdaptiveRisk()

    // PHASE 3: evaluate runtime risk continuously and escalate warning or block state
    const monitoringInterval = window.setInterval(() => {
      if (runtimeState.blocked) {
        window.clearInterval(monitoringInterval)
        return
      }

      const risk = getRuntimeRiskLevel()

      if (risk === 'CRITICAL' && !runtimeState.blocked) {
        runtimeState.blocked = true
        showBlockPage()
        window.clearInterval(monitoringInterval)
        return
      }

      if (risk === 'HIGH' && !runtimeState.warned) {
        runtimeState.warned = true
        showWarningBanner()
      }

      applyAdaptiveRisk()

      if (Date.now() - lastBackgroundSendAt >= SIGNAL_FLUSH_INTERVAL_MS) {
        scheduleSignalsToBackground()
      }
    }, MONITORING_INTERVAL_MS)
  })()
}
