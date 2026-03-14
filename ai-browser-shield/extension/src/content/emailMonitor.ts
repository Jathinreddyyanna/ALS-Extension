import type { EmailAnalysis, EmailRiskLabel, EmailScanInput } from '../types'

declare global {
  interface Window {
    __absEmailMonitorInstalled?: boolean
  }
}

const HOSTS = {
  gmail: 'mail.google.com',
  whatsapp: 'web.whatsapp.com',
  telegram: 'web.telegram.org',
} as const

const HIGHLIGHT_STYLE_ID = 'abs-email-monitor-styles'

function currentPlatform(): EmailScanInput['platform'] | null {
  const host = window.location.hostname
  if (host.includes(HOSTS.gmail)) return 'gmail'
  if (host.includes(HOSTS.whatsapp)) return 'whatsapp'
  if (host.includes(HOSTS.telegram)) return 'telegram'
  return null
}

function trimText(text: string): string {
  return text
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .join('\n')
    .trim()
}

function injectStyles() {
  if (document.getElementById(HIGHLIGHT_STYLE_ID)) return
  const style = document.createElement('style')
  style.id = HIGHLIGHT_STYLE_ID
  style.textContent = `
    .abs-email-highlight {
      transition: all 0.25s ease !important;
      box-sizing: border-box !important;
      border-radius: 8px !important;
      padding: 6px 10px !important;
    }
    .abs-email-processing {
      border: 3px solid transparent !important;
      background:
        linear-gradient(white, white) padding-box,
        linear-gradient(90deg, red, orange, yellow, green, blue, violet, red) border-box !important;
      background-size: 200% 200% !important;
      animation: absEmailRainbow 3s linear infinite !important;
      color: #111827 !important;
    }
    .abs-email-safe {
      background: #166534 !important;
      color: #fff !important;
      border: 2px solid #22c55e !important;
    }
    .abs-email-suspicious {
      background: #ca8a04 !important;
      color: #111827 !important;
      border: 2px solid #fde047 !important;
    }
    .abs-email-dangerous {
      background: #b91c1c !important;
      color: #fff !important;
      border: 2px solid #f87171 !important;
    }
    @keyframes absEmailRainbow {
      0% { background-position: 0% 50%; }
      100% { background-position: 200% 50%; }
    }
  `
  document.head.appendChild(style)
}

function isValidWhatsAppTitle(el: HTMLElement): boolean {
  const text = (el.innerText || '').trim().toLowerCase()
  const invalidStrings = ['click here', 'contact info', 'group info', 'online', 'typing...', 'last seen']
  if (!text || invalidStrings.some(value => text.includes(value))) return false
  if (text.length > 50) return false
  return el.offsetParent !== null
}

function getSubjectElement(platform: EmailScanInput['platform']): HTMLElement | null {
  if (platform === 'gmail') {
    const selectors = ['h2.hP', 'h2[data-subject-threading]', 'h2[role="heading"]', '[data-subject]', '.hP', '.ha h2', 'div[role="main"] h2']
    for (const selector of selectors) {
      const el = document.querySelector(selector)
      if (el instanceof HTMLElement) return el
    }
  }

  if (platform === 'whatsapp') {
    const header = document.querySelector('#main header')
    if (!header) return null
    const candidates = header.querySelectorAll('span[dir="auto"], div[role="button"] span')
    for (const candidate of candidates) {
      if (!(candidate instanceof HTMLElement)) continue
      if (isValidWhatsAppTitle(candidate)) return candidate
    }
  }

  if (platform === 'telegram') {
    const selectors = ['.chat-info .title', '.chat-title', '.peer-title', '.top-bar .title', 'div[class*="chat-title"]', '.tg_head_peer_title']
    for (const selector of selectors) {
      const el = document.querySelector(selector)
      if (el instanceof HTMLElement) return el
    }
  }

  return null
}

function resetHighlightStyles(el: HTMLElement) {
  const props = [
    'background',
    'background-color',
    'background-size',
    'animation',
    'color',
    'border',
    'border-radius',
    'padding',
    'box-sizing',
    'transition',
  ]
  for (const prop of props) {
    el.style.removeProperty(prop)
  }
}

function normalizeRiskLabel(label: string | null | undefined): EmailRiskLabel {
  const normalized = (label || '').toLowerCase().trim()
  if (normalized === 'dangerous' || normalized === 'scam' || normalized === 'phishing') return 'dangerous'
  if (normalized === 'suspicious' || normalized === 'warning' || normalized === 'warn') return 'suspicious'
  if (normalized === 'processing') return 'processing'
  if (normalized === 'error') return 'error'
  return 'safe'
}

function applyHighlight(platform: EmailScanInput['platform'], label: string) {
  const subjectEl = getSubjectElement(platform)
  if (!subjectEl) return
  const normalizedLabel = normalizeRiskLabel(label)

  subjectEl.classList.add('abs-email-highlight')
  subjectEl.classList.remove('abs-email-processing', 'abs-email-safe', 'abs-email-suspicious', 'abs-email-dangerous')
  resetHighlightStyles(subjectEl)

  subjectEl.style.setProperty('box-sizing', 'border-box', 'important')
  subjectEl.style.setProperty('display', 'inline-block', 'important')
  subjectEl.style.setProperty('border-radius', '8px', 'important')
  subjectEl.style.setProperty('padding', '6px 10px', 'important')
  subjectEl.style.setProperty('transition', 'all 0.25s ease', 'important')

  void subjectEl.offsetWidth

  if (normalizedLabel === 'processing') {
    subjectEl.classList.add('abs-email-processing')
    subjectEl.style.setProperty('border', '3px solid transparent', 'important')
    subjectEl.style.setProperty('background', 'linear-gradient(white, white) padding-box, linear-gradient(90deg, red, orange, yellow, green, blue, violet, red) border-box', 'important')
    subjectEl.style.setProperty('background-size', '200% 200%', 'important')
    subjectEl.style.setProperty('animation', 'absEmailRainbow 3s linear infinite', 'important')
    subjectEl.style.setProperty('color', '#111827', 'important')
  }

  if (normalizedLabel === 'safe') {
    subjectEl.classList.add('abs-email-safe')
    subjectEl.style.setProperty('background-color', '#2ecc40', 'important')
    subjectEl.style.setProperty('color', '#ffffff', 'important')
    subjectEl.style.setProperty('border', '2px solid #2ecc40', 'important')
  }

  if (normalizedLabel === 'suspicious') {
    subjectEl.classList.add('abs-email-suspicious')
    subjectEl.style.setProperty('background-color', '#ffcc00', 'important')
    subjectEl.style.setProperty('color', '#000000', 'important')
    subjectEl.style.setProperty('border', '2px solid #ffcc00', 'important')
  }

  if (normalizedLabel === 'dangerous') {
    subjectEl.classList.add('abs-email-dangerous')
    subjectEl.style.setProperty('background-color', '#ff3b3b', 'important')
    subjectEl.style.setProperty('color', '#ffffff', 'important')
    subjectEl.style.setProperty('border', '2px solid #ff3b3b', 'important')
  }

  subjectEl.setAttribute('data-abs-email-risk', normalizedLabel)
}

function extractLinks(root: ParentNode): string[] {
  return Array.from(root.querySelectorAll('a[href]'))
    .map(node => (node as HTMLAnchorElement).href)
    .filter(Boolean)
    .slice(0, 12)
}

function extractGmail(): EmailScanInput {
  const subject = (getSubjectElement('gmail')?.innerText || '').trim()
  const from = (document.querySelector('.gD') as HTMLElement | null)?.innerText?.trim() || ''
  const fromEmail = (document.querySelector('.gD') as HTMLElement | null)?.getAttribute('email') || ''

  let body = ''
  const candidates = document.querySelectorAll('.a3s.aiL, .a3s.ajx, [role="main"] .mGp')
  for (const node of candidates) {
    if (node instanceof HTMLElement && node.offsetHeight > 0) {
      body = trimText(node.innerText)
      break
    }
  }

  const root = (Array.from(candidates).find(n => n instanceof HTMLElement && n.offsetHeight > 0) as ParentNode | undefined) || document

  return {
    subject,
    from,
    fromEmail,
    body: body.slice(0, 1800),
    links: extractLinks(root),
    platform: 'gmail',
  }
}

function extractWhatsApp(): EmailScanInput {
  const subject = (getSubjectElement('whatsapp')?.innerText || '').trim()
  const textNodes = Array.from(document.querySelectorAll('.copyable-text span'))
  const body = trimText(
    textNodes
      .slice(-25)
      .map(node => (node as HTMLElement).innerText.trim())
      .filter(Boolean)
      .join('\n')
  ).slice(0, 1800)

  return {
    subject,
    from: subject,
    body,
    links: extractLinks(document),
    platform: 'whatsapp',
  }
}

function extractTelegram(): EmailScanInput {
  const subject = (getSubjectElement('telegram')?.innerText || '').trim()
  const msgs = Array.from(document.querySelectorAll('.message .text-content, .message .message-text, .message-content-wrapper'))
  const body = trimText(
    msgs
      .slice(-12)
      .map(node => (node as HTMLElement).innerText?.trim() || '')
      .filter(Boolean)
      .join('\n')
  ).slice(0, 1800)

  return {
    subject,
    from: subject,
    body,
    links: extractLinks(document),
    platform: 'telegram',
  }
}

function extractPayload(platform: EmailScanInput['platform']): EmailScanInput {
  if (platform === 'gmail') return extractGmail()
  if (platform === 'whatsapp') return extractWhatsApp()
  return extractTelegram()
}

export function initEmailMonitor() {
  if (window.__absEmailMonitorInstalled) return
  window.__absEmailMonitorInstalled = true

  const platform = currentPlatform()
  if (!platform) return

  injectStyles()

  let lastStable = ''
  let candidate = ''
  let sameCount = 0
  let lastSubject = ''
  let lastAppliedLabel: EmailRiskLabel | null = null
  let reinforceTimer: number | null = null

  function reinforceLabel(label: EmailRiskLabel) {
    if (reinforceTimer) window.clearInterval(reinforceTimer)
    let runs = 0
    reinforceTimer = window.setInterval(() => {
      applyHighlight(platform, label)
      runs += 1
      if (runs >= 8 && reinforceTimer) {
        window.clearInterval(reinforceTimer)
        reinforceTimer = null
      }
    }, 500)
  }

  const observer = new MutationObserver(() => {
    const subjectEl = getSubjectElement(platform)
    if (!subjectEl) return
    const currentText = subjectEl.innerText.trim()
    if (currentText && currentText !== lastSubject) {
      lastSubject = currentText
      lastAppliedLabel = 'processing'
      applyHighlight(platform, 'processing')
    } else if (currentText && lastAppliedLabel) {
      applyHighlight(platform, lastAppliedLabel)
    }
  })
  observer.observe(document.body, { childList: true, subtree: true, characterData: true })

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type !== 'EMAIL_ANALYSIS_RESULT') return false
    const analysis = message.payload as EmailAnalysis
    applyHighlight(platform, analysis.riskLabel)
    lastAppliedLabel = normalizeRiskLabel(analysis.riskLabel)
    reinforceLabel(lastAppliedLabel)
    lastSubject = analysis.subject || lastSubject
    sendResponse({ ok: true })
    return true
  })

  setInterval(() => {
    const payload = extractPayload(platform)
    if (payload.subject && payload.subject !== lastSubject) {
      applyHighlight(platform, 'processing')
      lastAppliedLabel = 'processing'
      lastSubject = payload.subject
    } else if (lastAppliedLabel) {
      // Re-apply the final state if the host app re-rendered the header node.
      applyHighlight(platform, lastAppliedLabel)
    }

    if (!(payload.body.length > 20 || payload.subject.length > 6)) return

    const serialized = JSON.stringify(payload)
    if (serialized === candidate) {
      sameCount += 1
    } else {
      candidate = serialized
      sameCount = 1
    }

    if (sameCount < 2 || serialized === lastStable) return
    lastStable = serialized

    chrome.runtime.sendMessage({
      type: 'EMAIL_CONTENT_UPDATE',
      payload,
    }).catch(() => {})
  }, 900)
}
