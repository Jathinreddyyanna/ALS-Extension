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

    let lastBackgroundSendAt = 0
    let phishingScanComplete = false

    // PHASE 3: centralize score updates and cap runtime risk at 100
    function addScore(points: number) {
      runtimeState.runtimeScore = Math.min(100, runtimeState.runtimeScore + points)
    }

    function isSensitivePath() {
      return /login|signin|auth|account|verify|secure|checkout|payment|billing|wallet/i.test(
        `${window.location.pathname} ${document.title}`
      )
    }

    function applyAdaptiveRisk() {
      let score = 0

      score += runtimeState.popupCount * WEIGHTS.popup
      score += runtimeState.redirectCount * WEIGHTS.redirect
      score += runtimeState.hiddenIframeCount * WEIGHTS.hiddenIframe
      score += runtimeState.overlayCount * WEIGHTS.overlay
      score += runtimeState.scriptInjectionCount * WEIGHTS.scriptInjection
      score += runtimeState.suspiciousFormCount * WEIGHTS.suspiciousForm
      score += runtimeState.earlyUnloadCount * WEIGHTS.earlyUnload

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
            },
          },
        }, () => {
          void chrome.runtime.lastError
        })
      } catch {
        // Extension context may be invalidated — silently ignore.
      }
    }

    // PHASE 3: show a single non-blocking runtime warning banner
    function showWarningBanner() {
      if (document.getElementById('abs-warning-banner')) return

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
                This interaction is dangerous and should be blocked immediately.
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
                  I understand the risks, continue anyway
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
          console.debug('[ABS] popup intercepted')

        applyAdaptiveRisk()
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
        }
      })
    }

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

          applyAdaptiveRisk()
        }

        if (tagName === 'SCRIPT' && Date.now() - runtimeState.startTime > 2000) {
          runtimeState.scriptInjectionCount += 1
          const script = element as HTMLScriptElement
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

        scanSensitiveInputs(element)
        applyAdaptiveRisk()
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

      if (Date.now() - lastBackgroundSendAt >= 4000) {
        lastBackgroundSendAt = Date.now()
        sendSignalsToBackground()
      }
    }, 2000)
  })()
}
