/**
 * Early guard content script - runs in ISOLATED world, injects the page-world
 * hook script, and relays redirect attempt messages to the background worker.
 */

const PAGE_EVENT_TYPE = 'ABS_EARLY_REDIRECT_ATTEMPT'
const INJECTED_ATTR = 'data-abs-early-guard'

type EarlyRedirectPayload = {
  url: string
  timestamp: number
  method: 'assign' | 'replace' | 'href'
}

function sendMessageSafe(payload: EarlyRedirectPayload) {
  try {
    chrome.runtime.sendMessage({
      type: 'EARLY_REDIRECT_ATTEMPT',
      payload,
    }, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore extension context failures.
  }
}

/**
 * Sets up the message relay from the page-world injected script
 * to the background service worker.
 */
export function hookEarlyRedirects() {
  try {
    if (document.documentElement.hasAttribute(INJECTED_ATTR)) {
      return
    }
    document.documentElement.setAttribute(INJECTED_ATTR, '1')

    window.addEventListener('message', (event: MessageEvent) => {
      if (event.source !== window || !event.data || event.data.type !== PAGE_EVENT_TYPE) return
      const payload = event.data.payload as EarlyRedirectPayload | undefined
      if (!payload?.url) return
      sendMessageSafe(payload)
    })

    const script = document.createElement('script')
    script.src = chrome.runtime.getURL('earlyGuardInjected.js')
    script.setAttribute('data-shield-injected', '1')
    script.async = false
    script.onload = () => script.remove()
    script.onerror = () => script.remove()
    ;(document.head || document.documentElement).appendChild(script)
  } catch {
    // Never break page execution.
  }
}

hookEarlyRedirects()
