const POPUP_THRESHOLD = 3

export function initPopupMonitor() {
  let popupCount = 0
  const _open = window.open.bind(window)

  window.open = function (...args) {
    popupCount++
    if (popupCount > POPUP_THRESHOLD) {
      chrome.runtime.sendMessage({ type: 'POPUP_ATTEMPT', payload: { count: popupCount, url: args[0] } })
      showPopupBlockedBanner(popupCount)
      return null
    }
    return _open(...args)
  }

  // Also watch for new full-screen overlays injected by the page
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node instanceof HTMLElement) {
          const style = window.getComputedStyle(node)
          if (style.position === 'fixed' && style.zIndex && parseInt(style.zIndex) > 9000) {
            const allowedId = node.id === 'risk-reopen-chip' || node.id === 'phishing-detection-banner'
            if (!node.id?.startsWith('abs-') && !allowedId) {
              node.style.display = 'none'
              popupCount++
              showPopupBlockedBanner(popupCount)
            }
          }
        }
      }
    }
  })
  observer.observe(document.body, { childList: true, subtree: false })
}

function showPopupBlockedBanner(count: number) {
  const existing = document.getElementById('abs-popup-banner')
  if (existing) {
    existing.querySelector('.abs-count')!.textContent = `${count} popups blocked`
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
