import { initHoverPreview } from './hoverPreview'
import { injectOverlay, showWarningOverlay, showDownloadWarning, showClickjackWarning } from './overlayInjector'
import { collectInteractionSignals } from './interactionDetector'
import { initLinkInterceptor } from '../preclick/linkInterceptor'
import { initRuntimeMonitor } from './runtimeMonitor'

const SHIELD_POPUP_KEY = 'data-shield-injected'
const TRACKING_PARAMS = [
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'fbclid',
  'gclid',
  'msclkid',
  'mc_eid',
  'yclid',
  'dclid',
  'igshid',
  '_openstat',
  '_hsenc',
  '_hsmi',
  'mkt_tok',
  'trk',
  'trkCampaign',
]

function sendRuntimeMessageSafe(message: unknown) {
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore extension messaging failures.
  }
}

function showShieldRedirectWarning(count: number) {
  if (document.querySelector('[data-shield-redirect-bar]')) return

  const bar = document.createElement('div')
  bar.setAttribute(SHIELD_POPUP_KEY, '1')
  bar.setAttribute('data-shield-redirect-bar', '1')
  Object.assign(bar.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    zIndex: '2147483645',
    background: '#D97706',
    color: '#ffffff',
    fontSize: '13px',
    fontFamily: 'system-ui, sans-serif',
    padding: '8px 16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    boxSizing: 'border-box',
    boxShadow: '0 2px 8px rgba(0,0,0,0.25)',
  })

  const msg = document.createElement('span')
  msg.textContent = `Shield: This site redirected ${count} time${count === 1 ? '' : 's'} before arriving here. Be cautious.`

  const close = document.createElement('button')
  close.textContent = 'X'
  Object.assign(close.style, {
    background: 'transparent',
    border: 'none',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    padding: '0 4px',
    lineHeight: '1',
  })
  close.setAttribute('aria-label', 'Dismiss')
  close.onclick = () => bar.remove()

  bar.appendChild(msg)
  bar.appendChild(close)
  document.documentElement.appendChild(bar)

  window.setTimeout(() => bar.remove(), 8000)
}

function stripTrackingParams() {
  try {
    const url = new URL(window.location.href)
    let changed = false

    for (const param of TRACKING_PARAMS) {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param)
        changed = true
      }
    }

    if (changed) {
      window.history.replaceState(window.history.state, '', url.toString())
    }
  } catch {
    // Ignore malformed URLs or replaceState failures.
  }
}

// Init all content-script features
initHoverPreview()
injectOverlay()
initLinkInterceptor()
stripTrackingParams()

// Listen for messages from background SW
// Note: overlayInjector sends OPEN_REPORT_FORM and CANCEL_DOWNLOAD directly to background
// via chrome.runtime.sendMessage; no relay needed here
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'SHOW_OVERLAY') {
    showWarningOverlay(message.payload)
  }
  if (message.type === 'REDIRECT_WARNING') {
    showShieldRedirectWarning(message.payload?.count ?? 2)
  }
  if (message.type === 'DOWNLOAD_WARNING') {
    showDownloadWarning(message.payload)
  }
  if (message.type === 'CLICKJACK_WARNING') {
    showClickjackWarning(message.payload)
  }
})

;(() => {
  const VS = 'data-vs'
  const SCAN_DELAY = 900

  function findLoginFields() {
    const pwEl = document.querySelector<HTMLInputElement>(
      `input[type="password"]:not([${VS}-filled])`
    )
    if (!pwEl) return { pwEl: null, userEl: null }

    const scope = pwEl.closest('form') ?? document
    const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>(
      'input[type="text"],input[type="email"],input[autocomplete="username"],input[autocomplete="email"]'
    ))
    const userEl = inputs.find((el) => {
      const hint = [el.labels?.[0]?.textContent, el.placeholder, el.name, el.id, el.autocomplete]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return /user|email|login|phone|account/.test(hint)
    }) ?? inputs.at(-1) ?? null

    return { pwEl, userEl }
  }

  function getSelector(el: HTMLElement): string {
    if (el.id) return `#${CSS.escape(el.id)}`
    const name = el.getAttribute('name')
    if (name) return `[name="${name}"]`
    return el.tagName.toLowerCase()
  }

  function injectAutofillButton(userEl: HTMLInputElement | null, pwEl: HTMLInputElement) {
    if (document.querySelector(`[${VS}-btn]`)) return

    const btn = document.createElement('button')
    btn.setAttribute(`${VS}-btn`, '1')
    btn.setAttribute('data-shield-injected', '1')
    btn.type = 'button'
    btn.textContent = 'Autofill'
    Object.assign(btn.style, {
      position: 'fixed',
      zIndex: '2147483630',
      background: 'linear-gradient(135deg,#0D9B6A,#065F46)',
      color: '#fff',
      border: 'none',
      borderRadius: '8px',
      padding: '5px 12px',
      fontSize: '12px',
      fontFamily: 'system-ui,sans-serif',
      cursor: 'pointer',
      boxShadow: '0 2px 12px rgba(13,155,106,0.4)',
    })

    const rect = pwEl.getBoundingClientRect()
    btn.style.top = `${Math.max(8, rect.top - 36)}px`
    btn.style.left = `${Math.min(rect.right - 110, window.innerWidth - 130)}px`

    btn.addEventListener('click', () => {
      if (!window.location.hostname || window.location.hostname === 'newtab') {
        btn.remove()
        return
      }

      sendRuntimeMessageSafe({
        type: 'VAULT_AUTOFILL_REQUEST',
        payload: {
          url: window.location.href,
          domain: window.location.hostname,
          usernameSelector: userEl ? getSelector(userEl) : null,
          passwordSelector: getSelector(pwEl),
        },
      })
      btn.remove()
    })

    document.documentElement.appendChild(btn)
    window.setTimeout(() => {
      if (btn.isConnected) btn.remove()
    }, 10_000)
  }

  function performAutofill(payload: {
    username: string
    password: string
    usernameSelector: string | null
    passwordSelector: string
  }) {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      'value'
    )?.set

    const fill = (el: HTMLInputElement, value: string) => {
      setter?.call(el, value)
      el.dispatchEvent(new Event('input', { bubbles: true }))
      el.dispatchEvent(new Event('change', { bubbles: true }))
      el.setAttribute(`${VS}-filled`, '1')
    }

    if (payload.usernameSelector) {
      const usernameEl = document.querySelector<HTMLInputElement>(payload.usernameSelector)
      if (usernameEl) fill(usernameEl, payload.username)
    }

    const passwordEl = document.querySelector<HTMLInputElement>(payload.passwordSelector)
    if (passwordEl) fill(passwordEl, payload.password)
  }

  function showSavePrompt(username: string, password: string) {
    if (document.querySelector(`[${VS}-save]`)) return

    const bar = document.createElement('div')
    bar.setAttribute('data-shield-injected', '1')
    bar.setAttribute(`${VS}-save`, '1')
    Object.assign(bar.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '100%',
      zIndex: '2147483644',
      background: '#1a1f2e',
      color: '#F4F4F2',
      padding: '10px 16px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      fontFamily: 'system-ui,sans-serif',
      fontSize: '13px',
      boxShadow: '0 2px 16px rgba(0,0,0,0.6)',
      boxSizing: 'border-box',
    })

    const left = document.createElement('span')
    left.innerHTML = '<strong>VaultShield</strong> - Save this password?'

    const right = document.createElement('div')
    right.style.cssText = 'display:flex;gap:8px'

    const makeBtn = (text: string, bg: string, fg: string) => {
      const button = document.createElement('button')
      button.textContent = text
      button.setAttribute('data-shield-injected', '1')
      Object.assign(button.style, {
        background: bg,
        color: fg,
        border: bg === 'transparent' ? '1px solid #374151' : 'none',
        borderRadius: '6px',
        padding: '4px 14px',
        cursor: 'pointer',
        fontSize: '12px',
      })
      return button
    }

    const saveBtn = makeBtn('Save', '#0D9B6A', '#fff')
    saveBtn.onclick = () => {
      sendRuntimeMessageSafe({
        type: 'VAULT_SAVE_ACCEPTED',
        payload: { domain: location.hostname, url: location.href, username, password },
      })
      bar.remove()
    }

    const noBtn = makeBtn('Not now', 'transparent', '#9CA3AF')
    noBtn.onclick = () => bar.remove()

    right.append(saveBtn, noBtn)
    bar.append(left, right)
    document.documentElement.appendChild(bar)
    window.setTimeout(() => {
      if (bar.isConnected) bar.remove()
    }, 15_000)
  }

  function showPhishingBlock(payload: {
    score: number
    reasons: string[]
    storedDomain: string
  }) {
    if (document.querySelector(`[${VS}-block]`)) return

    const bar = document.createElement('div')
    bar.setAttribute('data-shield-injected', '1')
    bar.setAttribute(`${VS}-block`, '1')
    Object.assign(bar.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '100%',
      zIndex: '2147483647',
      background: '#7F1D1D',
      color: '#FEE2E2',
      padding: '12px 16px',
      fontFamily: 'system-ui,sans-serif',
      fontSize: '13px',
      boxShadow: '0 4px 20px rgba(0,0,0,0.7)',
      boxSizing: 'border-box',
    })

    const closeId = `vs-close-${Date.now()}`
    bar.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
        <div>
          <div style="font-weight:700;margin-bottom:4px">
            VaultShield blocked autofill - Trust score: ${payload.score}/100
          </div>
          <div style="font-size:11px;opacity:0.85">
            ${payload.reasons.slice(0, 2).join(' · ')}
          </div>
        </div>
        <button id="${closeId}" data-shield-injected="1"
          style="background:transparent;border:1px solid #FCA5A5;color:#FEE2E2;
                 border-radius:6px;padding:3px 10px;cursor:pointer;font-size:12px;white-space:nowrap">
          Dismiss
        </button>
      </div>
    `
    document.documentElement.appendChild(bar)
    document.getElementById(closeId)?.addEventListener('click', () => bar.remove())
    window.setTimeout(() => {
      if (bar.isConnected) bar.remove()
    }, 12_000)
  }

  document.addEventListener('submit', (event) => {
    sendRuntimeMessageSafe({ type: 'FORM_SUBMITTED' })

    const form = event.target as HTMLFormElement
    const pwEl = form.querySelector<HTMLInputElement>('input[type="password"]')
    if (!pwEl?.value || pwEl.value.length < 4) return
    const userEl = form.querySelector<HTMLInputElement>(
      'input[type="text"],input[type="email"],input[autocomplete="username"]'
    )
    window.setTimeout(() => showSavePrompt(userEl?.value ?? '', pwEl.value), 700)
  }, true)

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'VAULT_DO_AUTOFILL') performAutofill(msg.payload)
    if (msg.type === 'VAULT_AUTOFILL_BLOCKED') showPhishingBlock(msg.payload)
  })

  window.setTimeout(() => {
    const { pwEl, userEl } = findLoginFields()
    if (pwEl) injectAutofillButton(userEl, pwEl)
  }, SCAN_DELAY)

  const vsObs = new MutationObserver(() => {
    if (!document.querySelector(`[${VS}-btn]`)) {
      const { pwEl, userEl } = findLoginFields()
      if (pwEl) injectAutofillButton(userEl, pwEl)
    }
  })
  vsObs.observe(document.documentElement, { childList: true, subtree: true })
})()

window.addEventListener('load', () => {
  try {
    const domSignals = collectInteractionSignals()
    const hasAnySignal = Object.values(domSignals).some((value) => (value ?? 0) > 0)

    if (hasAnySignal) {
      sendRuntimeMessageSafe({
        type: 'DOM_SIGNALS_COLLECTED',
        payload: domSignals,
      })
    }
  } catch {
    // Silently ignore DOM signal collection errors.
  }
}, { once: true })

// PHASE 3: initialize autonomous runtime monitoring after the DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initRuntimeMonitor, { once: true })
} else {
  initRuntimeMonitor()
}
