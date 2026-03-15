const STYLES = `
  @keyframes absSlideDown { from { opacity:0;transform:translateY(-20px) } to { opacity:1;transform:translateY(0) } }
  @keyframes absPulse { 0%,100% { transform:scale(1) } 50% { transform:scale(1.05) } }
  #abs-overlay * { box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif; }
  #abs-warning-bar * { box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif; }
`

function sendRuntimeMessageSafe(message: unknown) {
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore service worker/message port availability errors.
  }
}

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
  if (!document.body) return
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
    CRITICAL: '#FF1744',
    HIGH: '#FF6B00',
    MEDIUM: '#FFB300',
  }
  const bgColor = riskColors[riskLevel] || '#FFB300'
  const emoji = isCritical ? '??' : '??'
  const headline = isCritical
    ? '?? DANGER ? This Page Has Been Blocked'
    : '?? WARNING ? Suspicious Site Detected'


  overlay.innerHTML = `
    <div style="
      background:#0F172A;border:2px solid ${bgColor};border-radius:20px;
      padding:40px;max-width:520px;width:90%;text-align:center;
      box-shadow:0 25px 60px rgba(0,0,0,0.8);animation:absPulse 2s ease infinite;
    ">
      <div style="font-size:56px;margin-bottom:16px">${emoji}</div>
      <div style="
        display:inline-block;background:${bgColor};color:#fff;
        padding:8px 20px;border-radius:100px;font-size:14px;font-weight:800;
        letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;
      ">${riskLevel} RISK — Score: ${score}/100</div>
      <h2 style="color:#fff;font-size:26px;font-weight:900;margin:0 0 12px">
        ${headline}
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
    sendRuntimeMessageSafe({ type: 'OPEN_REPORT_FORM', payload: { url } })
    removeOverlay()
  })
}

export function showRedirectWarning(payload: { count: number; urls: string[]; url: string }) {
  if (!document.body) return
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

export function showClickjackWarning(payload: {
  blockedUrl: string
  score: number
  riskLevel: string
  reason: string
}) {
  if (!document.body) return

  document.getElementById('abs-clickjack-bar')?.remove()

  const bar = document.createElement('div')
  bar.id = 'abs-clickjack-bar'
  bar.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:linear-gradient(135deg,#7C2D12,#991B1B);
    color:#fff;padding:0;
    font-family:system-ui,sans-serif;
    box-shadow:0 4px 24px rgba(0,0,0,0.6);
    animation:absSlideDown 0.3s ease;
  `

  let hostname = ''
  try { hostname = new URL(payload.blockedUrl).hostname } catch { hostname = payload.blockedUrl }

  bar.innerHTML = `
    <div style="padding:12px 16px;display:flex;align-items:center;gap:12px;">
      <div style="
        width:36px;height:36px;border-radius:10px;flex-shrink:0;
        background:rgba(255,255,255,0.15);
        display:flex;align-items:center;justify-content:center;
        font-size:20px;
      ">🪤</div>
      <div style="flex:1;min-width:0;">
        <div style="font-weight:800;font-size:13px;margin-bottom:2px;">
          Click-Jacking Blocked!
        </div>
        <div style="font-size:11px;opacity:0.85;line-height:1.4;">
          ${payload.reason}
        </div>
        <div style="
          margin-top:4px;font-size:10px;opacity:0.6;
          overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
        ">
          Blocked: ${hostname}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0;">
        <button id="abs-cj-report" style="
          background:rgba(255,255,255,0.2);color:#fff;border:none;
          padding:6px 12px;border-radius:7px;cursor:pointer;
          font-size:11px;font-weight:700;
        ">🚩 Report</button>
        <button id="abs-cj-dismiss" style="
          background:transparent;color:rgba(255,255,255,0.6);border:none;
          padding:6px 10px;border-radius:7px;cursor:pointer;font-size:16px;
        ">×</button>
      </div>
    </div>
  `

  document.body.prepend(bar)

  document.getElementById('abs-cj-report')?.addEventListener('click', () => {
    sendRuntimeMessageSafe({ type: 'OPEN_REPORT_FORM', payload: { url: payload.blockedUrl } })
    bar.remove()
  })
  document.getElementById('abs-cj-dismiss')?.addEventListener('click', () => bar.remove())

  setTimeout(() => bar?.remove(), 8000)
}

export function showDownloadWarning(payload: {
  filename: string
  downloadId: number
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  explanation: string
  confidence: number
  indicators: string[]
  recommendedAction: string
  sourceDomain: string
  domainRiskScore: number
  domainReportCount: number
  sourceRisk: 'safe' | 'suspicious' | 'dangerous'
}) {
  if (!document.body) return
  removeOverlay()

  const {
    filename,
    downloadId,
    verdict,
    explanation,
    confidence,
    indicators,
    sourceDomain,
    domainRiskScore,
    domainReportCount,
  } = payload

  const isMalicious = verdict === 'MALICIOUS'
  const isSuspicious = verdict === 'SUSPICIOUS'

  const colors = {
    MALICIOUS: { accent: '#FF1744', bg: '#1A0505', border: '#FF174433', badge: 'rgba(255,23,68,0.15)', badgeText: '#FF6B6B' },
    SUSPICIOUS: { accent: '#FF6B00', bg: '#150A00', border: '#FF6B0033', badge: 'rgba(255,107,0,0.15)', badgeText: '#FF9A4D' },
    SAFE: { accent: '#00C851', bg: '#040E08', border: '#00C85133', badge: 'rgba(0,200,81,0.12)', badgeText: '#00E676' },
  }
  const c = colors[verdict]

  const ext = filename.split('.').pop()?.toUpperCase() || 'FILE'
  const confidencePct = Math.round(confidence * 100)

  const sourceRiskPill = domainRiskScore > 0 ? `
    <div style="display:inline-flex;align-items:center;gap:4px;
      background:${domainRiskScore >= 75 ? 'rgba(255,23,68,0.15)' : domainRiskScore >= 30 ? 'rgba(255,107,0,0.12)' : 'rgba(0,200,81,0.1)'};
      border:1px solid ${domainRiskScore >= 75 ? 'rgba(255,23,68,0.3)' : domainRiskScore >= 30 ? 'rgba(255,107,0,0.25)' : 'rgba(0,200,81,0.2)'};
      color:${domainRiskScore >= 75 ? '#FF6B6B' : domainRiskScore >= 30 ? '#FF9A4D' : '#00E676'};
      padding:3px 8px;border-radius:6px;font-size:10px;font-weight:700;margin-top:4px;">
      ${sourceDomain || 'Unknown source'} - Risk ${domainRiskScore}/100
      ${domainReportCount > 0 ? `? ${domainReportCount} reports` : ''}
    </div>
  ` : ''

  const indicatorsList = indicators.slice(0, 4).map((ind) => `
    <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;">
      <div style="width:16px;height:16px;border-radius:4px;flex-shrink:0;margin-top:1px;
        background:${c.badge};color:${c.badgeText};
        display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:900;">!</div>
      <span style="color:#8899BB;font-size:12px;line-height:1.4;">${ind}</span>
    </div>
  `).join('')

  const overlay = document.createElement('div')
  overlay.id = 'abs-overlay'
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;
    background:rgba(4,6,14,0.94);
    display:flex;align-items:center;justify-content:center;
    animation:absSlideDown 0.25s ease;
  `

  overlay.innerHTML = `
    <div style="
      background:${c.bg};
      border:2px solid ${c.border};
      border-radius:20px;padding:28px;
      max-width:440px;width:92%;
      box-shadow:0 32px 64px rgba(0,0,0,0.9);
      font-family:system-ui,-apple-system,sans-serif;
    ">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px;">
        <div style="
          width:52px;height:52px;border-radius:14px;flex-shrink:0;
          background:${c.badge};border:1.5px solid ${c.border};
          display:flex;align-items:center;justify-content:center;
          font-size:26px;
        ">${isMalicious ? '??' : isSuspicious ? '??' : '?'}</div>
        <div>
          <div style="color:${c.accent};font-size:16px;font-weight:900;line-height:1.2;">
            ${isMalicious ? 'DANGEROUS FILE DETECTED' : isSuspicious ? 'SUSPICIOUS FILE' : 'FILE LOOKS SAFE'}
          </div>
          <div style="color:#3D5070;font-size:11px;margin-top:3px;">
            AI Confidence: ${confidencePct}% - Powered by Gemini
          </div>
        </div>
      </div>

      <div style="
        background:#0D1524;border:1px solid #1A2740;
        border-radius:12px;padding:14px;margin-bottom:16px;
      ">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <div style="
            background:${c.badge};color:${c.accent};
            padding:4px 10px;border-radius:6px;
            font-size:11px;font-weight:800;letter-spacing:0.5px;
          ">.${ext}</div>
          <div style="color:#F0F4FF;font-size:13px;font-weight:600;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">
            ${filename}
          </div>
        </div>
        ${sourceRiskPill}
      </div>

      <div style="
        background:#0A1020;border-left:3px solid ${c.accent};
        border-radius:0 10px 10px 0;
        padding:12px 14px;margin-bottom:16px;
      ">
        <div style="color:#3D5070;font-size:10px;font-weight:700;
          text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">
          Gemini AI Analysis
        </div>
        <div style="color:#8899BB;font-size:12px;line-height:1.6;">
          ${explanation}
        </div>
      </div>

      ${indicators.length > 0 ? `
      <div style="margin-bottom:20px;">
        <div style="color:#3D5070;font-size:10px;font-weight:700;
          text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
          Risk Indicators
        </div>
        ${indicatorsList}
      </div>
      ` : ''}

      <div style="display:flex;gap:10px;">
        <button id="abs-dl-cancel" style="
          flex:1.5;padding:13px;
          background:${isMalicious ? '#FF1744' : '#FF6B00'};
          border:none;color:#fff;
          border-radius:12px;cursor:pointer;
          font-size:14px;font-weight:800;
          letter-spacing:-0.2px;
        ">Cancel Download</button>
        <button id="abs-dl-proceed" style="
          flex:1;padding:13px;
          background:transparent;
          border:1px solid #1A2740;
          color:#3D5070;
          border-radius:12px;cursor:pointer;
          font-size:12px;font-weight:600;
        ">Continue Anyway</button>
      </div>

      ${isMalicious ? `
      <div style="
        text-align:center;margin-top:12px;
        color:#FF1744;font-size:11px;font-weight:700;opacity:0.8;
      ">
        This file may harm your computer - cancelling is strongly recommended
      </div>
      ` : ''}
    </div>
  `

  document.body.appendChild(overlay)

  document.getElementById('abs-dl-cancel')?.addEventListener('click', () => {
    sendRuntimeMessageSafe({ type: 'CANCEL_DOWNLOAD', payload: { downloadId } })
    removeOverlay()
  })

  document.getElementById('abs-dl-proceed')?.addEventListener('click', () => {
    sendRuntimeMessageSafe({ type: 'ALLOW_DOWNLOAD', payload: { downloadId } })
    removeOverlay()
  })
}

function removeOverlay() {
  document.getElementById('abs-overlay')?.remove()
}
