const WARN_THRESHOLD = 3
const BLOCK_THRESHOLD = 5
const USER_GESTURE_WINDOW_MS = 1200

function sendRuntimeMessageSafe(message: unknown) {
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore service worker/message port availability errors.
  }
}

export function initPopupMonitor() {
  let popupCount = 0
  let lastUserGestureAt = 0
  let popupBudgetForGesture = 0
  const _open = window.open.bind(window)

  function markUserGesture() {
    lastUserGestureAt = Date.now()
    popupBudgetForGesture = 1
  }

  function hasRecentUserActivation(): boolean {
    return !!navigator.userActivation?.isActive || Date.now() - lastUserGestureAt <= USER_GESTURE_WINDOW_MS
  }

  document.addEventListener('pointerdown', markUserGesture, true)
  document.addEventListener('keydown', markUserGesture, true)
  document.addEventListener('submit', markUserGesture, true)
  document.addEventListener('touchstart', markUserGesture, true)

  window.open = function (...args) {
    popupCount++
    const targetUrl = (args[0] as string | undefined) || window.location.href
    const hasGesture = hasRecentUserActivation()
    const canUseGestureBudget = hasGesture && popupBudgetForGesture > 0
    const shouldBlock = !canUseGestureBudget || popupCount > BLOCK_THRESHOLD

    sendRuntimeMessageSafe({
      type: 'POPUP_ATTEMPT',
      payload: {
        count: popupCount,
        url: targetUrl,
        kind: 'window',
        hasGesture,
        blocked: shouldBlock,
      },
    })

    if (popupCount >= WARN_THRESHOLD) {
      showPopupBlockedBanner(popupCount)
    }

    if (shouldBlock) {
      return null
    }

    popupBudgetForGesture = 0
    return _open(...args)
  }

  // Also watch for new full-screen overlays injected by the page
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (!(node instanceof HTMLElement)) continue
        if (!node.id?.startsWith('abs-')) {
          try {
            const style = window.getComputedStyle(node)
            if (style.position === 'fixed' && parseInt(style.zIndex || '0', 10) > 9000) {
              node.style.display = 'none'
              popupCount++
              sendRuntimeMessageSafe({
                type: 'POPUP_ATTEMPT',
                payload: {
                  count: popupCount,
                  url: window.location.href,
                  kind: 'overlay',
                  isHidden: true,
                },
              })
              if (popupCount >= WARN_THRESHOLD) {
                showPopupBlockedBanner(popupCount)
              }
            }
          } catch {
            // Ignore nodes that fail style inspection.
          }
        }
      }
    }
  })
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true })
  }

  function blockOverlayAds() {
    const AD_SELECTORS = [
      '[id*="ad-"]:not([id^="abs"])',
      '[class*="ad-banner"]:not([id^="abs"])',
      '[class*="popup-ad"]:not([id^="abs"])',
      '[class*="overlay-ad"]:not([id^="abs"])',
      'iframe[src*="doubleclick"]',
      'iframe[src*="googlesyndication"]',
      'iframe[src*="adnxs"]',
      'div[data-ad-slot]',
      'ins.adsbygoogle',
    ]

    const hideMatches = () => {
      AD_SELECTORS.forEach(sel => {
        document.querySelectorAll<HTMLElement>(sel).forEach(el => {
          if (!el.id?.startsWith('abs-')) {
            el.style.setProperty('display', 'none', 'important')
          }
        })
      })
    }

    const adObserver = new MutationObserver(() => hideMatches())
    adObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class', 'id', 'style'],
    })

    hideMatches()
  }

  function blockBounceTrackers() {
    const BOUNCE_DOMAINS = ['l.facebook.com', 'l.instagram.com', 'lnkd.in', 't.co', 'bit.ly', 'click.email']

    document.addEventListener('click', (e) => {
      const a = (e.target as HTMLElement).closest('a')
      if (!a?.href) return
      try {
        const url = new URL(a.href)
        if (BOUNCE_DOMAINS.some(d => url.hostname.includes(d))) {
          const dest =
            url.searchParams.get('u') ||
            url.searchParams.get('url') ||
            url.searchParams.get('redirect')
          if (dest) {
            e.preventDefault()
            window.location.href = dest
          }
        }
      } catch {
        // Ignore malformed URLs
      }
    }, true)
  }

  blockOverlayAds()
  blockBounceTrackers()

  function blockInvisibleOverlays() {
    function findAndNeutralizeOverlays() {
      const allElements = document.querySelectorAll<HTMLElement>('*')

      for (const el of allElements) {
        if (el.id?.startsWith('abs-')) continue
        if (el.closest('[id^="abs-"]')) continue

        try {
          const style = window.getComputedStyle(el)
          const rect = el.getBoundingClientRect()
          const isFullscreen = rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8
          const isPositioned = style.position === 'fixed' || style.position === 'absolute'
          const isTransparent = parseFloat(style.opacity || '1') < 0.1
          const hasHighZ = parseInt(style.zIndex || '0', 10) > 100

          if (isFullscreen && isPositioned && isTransparent && hasHighZ) {
            el.style.setProperty('pointer-events', 'none', 'important')
            el.style.setProperty('display', 'none', 'important')
            popupCount++
            sendRuntimeMessageSafe({
              type: 'POPUP_ATTEMPT',
              payload: { count: popupCount, url: window.location.href, kind: 'overlay', trapType: 'clickjack_overlay' },
            })
            showPopupBlockedBanner(popupCount)
            continue
          }

          if (el.tagName === 'IFRAME') {
            const src = (el as HTMLIFrameElement).src || ''
            if (isFullscreen && isPositioned && hasHighZ && src && !src.startsWith(window.location.origin)) {
              el.style.setProperty('display', 'none', 'important')
              popupCount++
              showPopupBlockedBanner(popupCount)
            }
          }
        } catch {
          // Ignore nodes that cannot be inspected.
        }
      }
    }

    findAndNeutralizeOverlays()

    const overlayObserver = new MutationObserver(() => {
      window.setTimeout(findAndNeutralizeOverlays, 200)
    })

    overlayObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class'],
    })
  }

  function blockFakeCloseButtons() {
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement | null
      if (!target) return

      const candidate = target.closest('a,button,[role="button"]') as HTMLElement | null
      if (!candidate) return

      const text = candidate.textContent?.trim() || ''
      const isCloseButton = ['×', '✕', '✗', 'X', 'Close', 'Skip', 'close'].includes(text)
      const href = candidate instanceof HTMLAnchorElement ? candidate.href : ''

      if (isCloseButton && href) {
        try {
          const targetHost = new URL(href).hostname
          if (targetHost !== window.location.hostname) {
            e.preventDefault()
            e.stopPropagation()
            popupCount++
            showPopupBlockedBanner(popupCount)
            sendRuntimeMessageSafe({
              type: 'POPUP_ATTEMPT',
              payload: { count: popupCount, url: href, kind: 'overlay', trapType: 'fake_close_button' },
            })
          }
        } catch {
          // Ignore malformed URLs.
        }
      }
    }, true)
  }

  function enhanceWindowOpenBlock() {
    const nativeOpen = window.open.bind(window)
    let openCount = 0
    let lastOpenTime = 0

    window.open = function (...args) {
      const now = Date.now()
      openCount++
      const url = args[0]?.toString() || ''
      const timeSinceLast = now - lastOpenTime
      lastOpenTime = now
      const suspiciousPatterns = ['casino', 'prize', 'winner', 'free-spin', 'adult', 'xxx', 'download-now']
      const isSuspicious = timeSinceLast < 1000 || openCount > 1 || suspiciousPatterns.some((pattern) => url.toLowerCase().includes(pattern))

      if (isSuspicious) {
        sendRuntimeMessageSafe({
          type: 'POPUP_ATTEMPT',
          payload: { count: openCount, url, kind: 'window', trapType: 'window_open_spam' },
        })
        showPopupBlockedBanner(openCount)
        return null
      }

      return nativeOpen(...args)
    }
  }

  blockInvisibleOverlays()
  blockFakeCloseButtons()
  enhanceWindowOpenBlock()
}

function showPopupBlockedBanner(count: number) {
  if (!document.body) return
  const existing = document.getElementById('abs-popup-banner')
  if (existing) {
    const countNode = existing.querySelector('.abs-count')
    if (countNode) countNode.textContent = `${count} popups blocked`
    return
  }

  const banner = document.createElement('div')
  banner.id = 'abs-popup-banner'
  banner.style.cssText = `
    position:fixed;bottom:20px;right:20px;z-index:2147483647;
    background:#1E3A5F;color:#fff;padding:12px 18px;border-radius:12px;
    font-family:system-ui,sans-serif;font-size:13px;font-weight:600;
    box-shadow:0 4px 20px rgba(0,0,0,0.4);display:flex;align-items:center;gap:10px;
    animation:absSlideIn 0.3s ease;
  `
  banner.innerHTML = `
    <span style="font-size:18px">🛡️</span>
    <span class="abs-count">${count} popups blocked</span>
    <button onclick="this.parentElement.remove()" style="
      background:rgba(255,255,255,0.2);border:none;color:#fff;
      padding:4px 8px;border-radius:6px;cursor:pointer;font-size:11px;margin-left:8px;
    ">✕</button>
  `
  document.body.appendChild(banner)
  setTimeout(() => banner?.remove(), 4000)
}
