const STYLES = `
  @keyframes absSlideDown { from { opacity:0;transform:translateY(-20px) } to { opacity:1;transform:translateY(0) } }
  @keyframes absPulse { 0%,100% { transform:scale(1) } 50% { transform:scale(1.05) } }
  #abs-overlay * { box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif; }
  #abs-warning-bar * { box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif; }
`

export function injectOverlay() {
  const style = document.createElement('style')
  style.textContent = STYLES
  document.head.appendChild(style)
}

export function showWarningOverlay(payload: {
  url: string
  score: number
  riskLevel: string
  explanation: string
  recommendedAction: string
}) {
  removeOverlay()
  const { url, score, riskLevel, explanation, recommendedAction } = payload
  const isCritical = riskLevel === 'CRITICAL'

  const overlay = document.createElement('div')
  overlay.id = 'abs-overlay'
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;
    background:rgba(10,10,20,0.92);
    display:flex;align-items:center;justify-content:center;
    animation:absSlideDown 0.3s ease;
  `

  const riskColors: Record<string, string> = {
    CRITICAL: '#7F1D1D',
    HIGH: '#991B1B',
    MEDIUM: '#B45309',
  }
  const bgColor = riskColors[riskLevel] || '#B45309'
  const emoji = isCritical ? '🚨' : '⚠️'

  overlay.innerHTML = `
    <div style="
      background:#0F172A;border:2px solid ${bgColor};border-radius:20px;
      padding:40px;max-width:520px;width:90%;text-align:center;
      box-shadow:0 25px 60px rgba(0,0,0,0.8);animation:absPulse 2s ease infinite;
    ">
      <div style="font-size:56px;margin-bottom:16px">${emoji}</div>
      <div style="
        display:inline-block;background:${bgColor};color:#fff;
        padding:6px 16px;border-radius:100px;font-size:12px;font-weight:700;
        letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;
      ">${riskLevel} RISK — Score: ${score}/100</div>
      <h2 style="color:#fff;font-size:22px;font-weight:700;margin:0 0 12px">
        ${isCritical ? 'This Page Has Been Blocked' : 'Warning: Suspicious Website Detected'}
      </h2>
      <p style="color:#94A3B8;font-size:14px;line-height:1.7;margin:0 0 24px">${explanation}</p>
      <div style="
        background:#1E293B;border-radius:12px;padding:16px;margin-bottom:24px;
        border-left:4px solid ${bgColor};text-align:left;
      ">
        <div style="color:#64748B;font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:4px">Suspicious URL</div>
        <div style="color:#CBD5E1;font-size:12px;word-break:break-all">${url}</div>
      </div>
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;">
        <button id="abs-go-back" style="
          background:#166534;color:#fff;border:none;padding:12px 24px;
          border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
          flex:1;min-width:120px;transition:opacity 0.2s;
        ">← Go Back (Safe)</button>
        <button id="abs-report" style="
          background:#1D4ED8;color:#fff;border:none;padding:12px 24px;
          border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
          flex:1;min-width:120px;
        ">🚩 Report Site</button>
        ${recommendedAction !== 'block' ? `
        <button id="abs-proceed" style="
          background:#374151;color:#9CA3AF;border:1px solid #4B5563;padding:12px 24px;
          border-radius:10px;font-size:13px;cursor:pointer;flex:1;min-width:120px;
        ">Proceed Anyway</button>` : ''}
      </div>
    </div>
  `

  document.body.appendChild(overlay)

  document.getElementById('abs-go-back')?.addEventListener('click', () => {
    window.history.back()
    removeOverlay()
  })
  document.getElementById('abs-proceed')?.addEventListener('click', removeOverlay)
  document.getElementById('abs-report')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'OPEN_REPORT_FORM', payload: { url } })
    removeOverlay()
  })
}

export function showRedirectWarning(payload: { count: number; urls: string[]; url: string }) {
  const bar = document.createElement('div')
  bar.id = 'abs-warning-bar'
  bar.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:#7C2D12;color:#fff;padding:14px 20px;
    display:flex;align-items:center;justify-content:space-between;
    font-family:system-ui,sans-serif;animation:absSlideDown 0.3s ease;
    box-shadow:0 4px 20px rgba(0,0,0,0.5);
  `
  bar.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;">
      <span style="font-size:20px">⛔</span>
      <div>
        <div style="font-weight:700;font-size:14px">Redirect Attack Detected</div>
        <div style="font-size:12px;opacity:0.8">This link bounced through ${payload.count} websites before landing here.</div>
      </div>
    </div>
    <div style="display:flex;gap:8px;">
      <button id="abs-stop-redirect" style="
        background:#166534;color:#fff;border:none;padding:8px 16px;
        border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
      ">Go Back</button>
      <button id="abs-dismiss-bar" style="
        background:rgba(255,255,255,0.15);color:#fff;border:none;
        padding:8px 12px;border-radius:8px;cursor:pointer;font-size:13px;
      ">Dismiss</button>
    </div>
  `
  document.body.prepend(bar)
  document.getElementById('abs-stop-redirect')?.addEventListener('click', () => { window.history.back(); bar.remove() })
  document.getElementById('abs-dismiss-bar')?.addEventListener('click', () => bar.remove())
}

export function showDownloadWarning(payload: { filename: string; risk: { level: string; reason: string }; url: string; downloadId: number }) {
  removeOverlay()
  const overlay = document.createElement('div')
  overlay.id = 'abs-overlay'
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;
    background:rgba(10,10,20,0.88);
    display:flex;align-items:center;justify-content:center;
  `
  const isHigh = payload.risk.level === 'high'
  overlay.innerHTML = `
    <div style="
      background:#0F172A;border:2px solid ${isHigh ? '#991B1B' : '#B45309'};
      border-radius:20px;padding:36px;max-width:460px;width:90%;text-align:center;
      box-shadow:0 25px 60px rgba(0,0,0,0.8);
    ">
      <div style="font-size:48px;margin-bottom:12px">${isHigh ? '🚨' : '⚠️'}</div>
      <h2 style="color:#fff;font-size:20px;font-weight:700;margin:0 0 8px">
        ${isHigh ? 'Download Blocked' : 'Suspicious Download'}
      </h2>
      <div style="
        background:#1E293B;border-radius:10px;padding:14px;margin:16px 0;text-align:left;
      ">
        <div style="color:#64748B;font-size:11px;text-transform:uppercase;font-weight:600;margin-bottom:4px">File</div>
        <div style="color:#F1F5F9;font-size:14px;font-weight:600">${payload.filename}</div>
        <div style="color:#94A3B8;font-size:12px;margin-top:8px">${payload.risk.reason}</div>
      </div>
      <div style="display:flex;gap:10px;justify-content:center;">
        ${isHigh ? `
        <button id="abs-dl-ok" style="
          background:#166534;color:#fff;border:none;padding:12px 24px;
          border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;flex:1;
        ">OK, Got it</button>` : `
        <button id="abs-dl-cancel" style="
          background:#991B1B;color:#fff;border:none;padding:12px 24px;
          border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;flex:1;
        ">Cancel Download</button>
        <button id="abs-dl-proceed" style="
          background:#374151;color:#9CA3AF;border:1px solid #4B5563;
          padding:12px 24px;border-radius:10px;font-size:13px;cursor:pointer;flex:1;
        ">Download Anyway</button>`}
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  document.getElementById('abs-dl-ok')?.addEventListener('click', removeOverlay)
  document.getElementById('abs-dl-cancel')?.addEventListener('click', () => {
    // Content scripts can't call chrome.downloads directly — ask background to cancel
    chrome.runtime.sendMessage({ type: 'CANCEL_DOWNLOAD', payload: { downloadId: payload.downloadId } })
    removeOverlay()
  })
  document.getElementById('abs-dl-proceed')?.addEventListener('click', removeOverlay)
}

function removeOverlay() {
  document.getElementById('abs-overlay')?.remove()
}
