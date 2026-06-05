(() => {
  const payload = (globalThis as typeof globalThis & {
    __ABS_OVERLAY_PAYLOAD?: {
      score: number
      riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
      reasons: string[]
      domain: string
      url: string
    }
  }).__ABS_OVERLAY_PAYLOAD

  if (!payload || payload.score < 50) return

  document.getElementById('abs-live-overlay')?.remove()

  const overlay = document.createElement('div')
  overlay.id = 'abs-live-overlay'
  const isCritical = payload.riskLevel === 'CRITICAL'
  overlay.style.cssText = isCritical
    ? 'position:fixed;inset:0;z-index:2147483647;background:#2b0202;color:#fff;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;font-family:Inter,system-ui,sans-serif;'
    : 'position:fixed;inset:0;z-index:2147483647;background:rgba(60,0,0,0.82);color:#fff;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;font-family:Inter,system-ui,sans-serif;'

  const reasons = payload.reasons.slice(0, 6).map((reason) => `<li style="margin:6px 0;">${reason}</li>`).join('')
  overlay.innerHTML = isCritical
    ? `
      <div style="max-width:620px;width:100%;background:#3b0707;border:1px solid rgba(255,255,255,0.12);border-radius:24px;padding:32px;box-shadow:0 24px 80px rgba(0,0,0,0.55);text-align:left;">
        <div style="font-size:42px;margin-bottom:12px;">⚠</div>
        <div style="font-size:28px;font-weight:800;margin-bottom:10px;">BLOCKED: Confirmed Dangerous Site</div>
        <div style="font-size:15px;color:#fecaca;line-height:1.6;margin-bottom:18px;">This site has been identified as a phishing or scam page and has been blocked to protect your session.</div>
        <div style="font-size:13px;color:#fca5a5;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">Domain</div>
        <div style="font-size:18px;font-weight:700;margin-bottom:18px;">${payload.domain}</div>
        <div style="font-size:13px;color:#fca5a5;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">Detected signals</div>
        <ul style="padding-left:20px;margin:0 0 20px;">${reasons}</ul>
        <button id="abs-live-go-back" style="background:#16a34a;color:#fff;border:none;border-radius:12px;padding:14px 20px;font-weight:700;cursor:pointer;">Go Back to Safety</button>
      </div>
    `
    : `
      <div style="max-width:620px;width:100%;background:#140909;border:1px solid rgba(255,255,255,0.12);border-radius:24px;padding:32px;box-shadow:0 24px 80px rgba(0,0,0,0.55);text-align:left;">
        <div style="font-size:42px;margin-bottom:12px;">🛡</div>
        <div style="font-size:28px;font-weight:800;margin-bottom:10px;">Warning: This site looks dangerous</div>
        <div style="font-size:15px;color:#fecaca;line-height:1.6;margin-bottom:18px;">We detected: ${payload.reasons.slice(0, 3).join(' + ')}</div>
        <div style="font-size:18px;font-weight:700;margin-bottom:18px;">Risk Score: ${payload.score}/100</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;">
          <button id="abs-live-go-back" style="background:#16a34a;color:#fff;border:none;border-radius:12px;padding:14px 20px;font-weight:700;cursor:pointer;">Go Back to Safety</button>
          <button id="abs-live-proceed" style="background:transparent;color:#d1d5db;border:1px solid rgba(255,255,255,0.18);border-radius:12px;padding:14px 20px;cursor:pointer;">I understand the risk, proceed anyway</button>
        </div>
      </div>
    `

  document.documentElement.appendChild(overlay)

  document.getElementById('abs-live-go-back')?.addEventListener('click', () => {
    history.back()
    overlay.remove()
  })

  document.getElementById('abs-live-proceed')?.addEventListener('click', () => {
    try {
      chrome.runtime.sendMessage({
        type: 'LIVE_SIGNAL_DETECTED',
        payload: {
          signal: 'POPUP_TRAP',
          scoreIncrease: 0,
          url: payload.url,
          detail: 'User chose to proceed after live warning overlay',
          timestamp: Date.now(),
          acknowledged: true,
        },
      }, () => {
        void chrome.runtime.lastError
      })
    } catch {
      // Ignore extension context failures.
    }
    overlay.remove()
  })
})()
