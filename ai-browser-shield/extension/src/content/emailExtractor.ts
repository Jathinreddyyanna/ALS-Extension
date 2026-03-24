/**
 * Gmail Email Extractor
 * Source of truth: extracts visible email and sends it to background.
 * Background computes score once and both popup + overlay consume the same state.
 */


type RiskLabel = 'safe' | 'suspicious' | 'dangerous'
type EmailStatus = 'waiting' | 'analyzing' | 'ready'

interface EmailStateMessage {
  type: 'EMAIL_STATE_UPDATED'
  payload: {
    emailText: string
    riskScore: number
    riskLabel: RiskLabel
    status: EmailStatus
    explanation?: string
  }
}

function isEmailStatePayload(payload: unknown): payload is EmailStateMessage['payload'] {
  if (!payload || typeof payload !== 'object') return false
  const state = payload as Record<string, unknown>
  return (
    typeof state.riskScore === 'number' &&
    (state.riskLabel === 'safe' || state.riskLabel === 'suspicious' || state.riskLabel === 'dangerous') &&
    (state.status === 'waiting' || state.status === 'analyzing' || state.status === 'ready')
  )
}

const DETECTION_DEBOUNCE_MS = 250
const MAX_EMAIL_PAYLOAD_CHARS = 8000

let extractorDisabled = false
let observer: MutationObserver | null = null
let emailTimer: ReturnType<typeof setTimeout> | null = null
let lastExtractedText = ''
let lastEmailFingerprint = ''

function isExtensionContextValid(): boolean {
  try {
    return Boolean(chrome?.runtime?.id)
  } catch {
    return false
  }
}

function disableExtractor(reason: string): void {
  if (extractorDisabled) return
  extractorDisabled = true
  if (emailTimer) clearTimeout(emailTimer)
  observer?.disconnect()
}

function safeSendMessage(message: unknown): void {
  if (extractorDisabled) return
  if (!isExtensionContextValid()) {
    disableExtractor('extension context invalidated')
    return
  }

  try {
    chrome.runtime.sendMessage(message).catch((err) => {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('Extension context invalidated')) disableExtractor(msg)
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes('Extension context invalidated')) disableExtractor(msg)
  }
}

function isVisible(element: HTMLElement): boolean {
  const style = window.getComputedStyle(element)
  const rect = element.getBoundingClientRect()
  return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0
}

function getOpenedEmailBody(): HTMLElement | null {
  // Required selector from spec: .gs .a3s (primary)
  const primary = Array.from(document.querySelectorAll('.gs .a3s'))
    .filter((el): el is HTMLElement => el instanceof HTMLElement)
    .filter(isVisible)

  if (primary.length > 0) return primary[0]

  // Gmail layouts can vary (preview pane / spam view), so keep safe fallbacks.
  const fallback = Array.from(document.querySelectorAll('.a3s, .ii.gt .a3s, .adn .a3s'))
    .filter((el): el is HTMLElement => el instanceof HTMLElement)
    .filter(isVisible)

  if (fallback.length > 0) return fallback[0]

  return null
}

function extractSenderFromOpenedEmail(emailBody: HTMLElement): string {
  const emailRegex = /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/
  const container = emailBody.closest('.adn') || emailBody.closest('.ii.gt')

  if (container instanceof HTMLElement) {
    const senderNode = container.querySelector('.gD[email], .gD[data-hovercard-id], .go') as HTMLElement | null
    const candidate = senderNode?.getAttribute('email') || senderNode?.getAttribute('data-hovercard-id') || senderNode?.textContent || ''
    const match = candidate.match(emailRegex)
    if (match) return match[0].toLowerCase()

    const scoped = container.innerText.match(emailRegex)
    if (scoped) return scoped[0].toLowerCase()
  }

  return ''
}

function isSpamFolderContext(): boolean {
  return window.location.href.includes('#spam') || window.location.href.includes('in:spam')
}

function getRiskVisual(score: number) {
  if (score <= 25) {
    return {
      label: 'SAFE',
      background: '#16a34a',
      color: '#ffffff',
      bannerBackground: 'rgba(22, 163, 74, 0.12)',
      bannerBorder: 'rgba(22, 163, 74, 0.35)',
      bannerColor: '#166534',
    }
  }

  if (score <= 55) {
    return {
      label: 'SUSPICIOUS',
      background: '#facc15',
      color: '#111827',
      bannerBackground: 'rgba(250, 204, 21, 0.16)',
      bannerBorder: 'rgba(202, 138, 4, 0.35)',
      bannerColor: '#854d0e',
    }
  }

  if (score <= 80) {
    return {
      label: 'HIGH',
      background: '#f97316',
      color: '#ffffff',
      bannerBackground: 'rgba(249, 115, 22, 0.16)',
      bannerBorder: 'rgba(194, 65, 12, 0.35)',
      bannerColor: '#9a3412',
    }
  }

  return {
    label: 'CRITICAL',
    background: '#dc2626',
    color: '#ffffff',
    bannerBackground: 'rgba(220, 38, 38, 0.12)',
    bannerBorder: 'rgba(220, 38, 38, 0.35)',
    bannerColor: '#991b1b',
  }
}

function highlightSubject(score: number, riskLabel: RiskLabel): void {
  const subject = document.querySelector('h2.hP') as HTMLElement | null
  if (!subject) return

  const visual = getRiskVisual(score)

  subject.style.background = visual.background
  subject.style.color = visual.color
  subject.style.padding = '6px 10px'
  subject.style.borderRadius = '6px'
  subject.style.display = 'inline-block'
  subject.style.lineHeight = '1.4'

  let banner = document.getElementById('abs-gmail-risk-banner') as HTMLDivElement | null
  if (!banner) {
    banner = document.createElement('div')
    banner.id = 'abs-gmail-risk-banner'
    subject.insertAdjacentElement('afterend', banner)
  }

  banner.style.marginTop = '8px'
  banner.style.padding = '8px 10px'
  banner.style.borderRadius = '8px'
  banner.style.background = visual.bannerBackground
  banner.style.border = `1px solid ${visual.bannerBorder}`
  banner.style.color = visual.bannerColor
  banner.style.fontSize = '12px'
  banner.style.lineHeight = '1.45'
  banner.style.maxWidth = 'fit-content'
  banner.innerHTML = [
    '<div style="font-weight:700;">⚠ AI Browser Shield</div>',
    `<div>Risk Score: ${score}/100</div>`,
    `<div>${riskLabel.toUpperCase()}</div>`,
  ].join('')
}

function clearSubjectHighlight(): void {
  const subject = document.querySelector('h2.hP') as HTMLElement | null
  if (subject) {
    subject.style.background = ''
    subject.style.color = ''
    subject.style.padding = ''
    subject.style.borderRadius = ''
    subject.style.display = ''
    subject.style.lineHeight = ''
  }

  const banner = document.getElementById('abs-gmail-risk-banner')
  if (banner) banner.remove()
}

function clearEmailState(): void {
  if (!lastExtractedText && !lastEmailFingerprint) return
  lastExtractedText = ''
  lastEmailFingerprint = ''
  clearSubjectHighlight()
  safeSendMessage({ type: 'RESET_EMAIL_STATE' })
}

function getCurrentEmailFingerprint(emailBody: HTMLElement): string {
  const subject = (document.querySelector('h2.hP') as HTMLElement | null)?.innerText?.trim() || ''
  const sender = extractSenderFromOpenedEmail(emailBody)
  const bodySnippet = (emailBody.innerText || emailBody.textContent || '').trim().slice(0, 180)
  const route = window.location.hash || window.location.pathname
  return `${route}::${sender}::${subject}::${bodySnippet}`
}

function scheduleExtraction(): void {
  if (extractorDisabled) return
  if (emailTimer) clearTimeout(emailTimer)
  emailTimer = setTimeout(() => {
    extractEmail()
  }, DETECTION_DEBOUNCE_MS)
}

function extractEmail(): void {
  if (extractorDisabled) return

  const emailElement = getOpenedEmailBody()
  if (!emailElement) {
    clearEmailState()
    return
  }

  const emailText = (emailElement.innerText || emailElement.textContent || '').trim()
  if (!emailText || emailText.length <= 50) {
    return
  }

  const boundedEmailText = emailText.slice(0, MAX_EMAIL_PAYLOAD_CHARS)

  const fingerprint = getCurrentEmailFingerprint(emailElement)
  if (boundedEmailText === lastExtractedText && fingerprint === lastEmailFingerprint) {
    return
  }

  lastExtractedText = boundedEmailText
  lastEmailFingerprint = fingerprint
  const senderEmail = extractSenderFromOpenedEmail(emailElement)

  safeSendMessage({
    type: 'EMAIL_CONTENT',
    payload: {
      emailText: boundedEmailText,
      senderEmail,
      isSpamFolder: isSpamFolderContext(),
    },
  })
}

observer = new MutationObserver(() => {
  if (extractorDisabled) return
  scheduleExtraction()
})

function initializeObserver(): void {
  if (extractorDisabled) return
  if (!isExtensionContextValid()) {
    disableExtractor('extension context invalidated at init')
    return
  }

  // Keep initialization silent in production to reduce console noise.
  observer?.observe(document.body, {
    childList: true,
    subtree: true,
  })

  safeSendMessage({ type: 'RESET_EMAIL_STATE' })

  // Initial extraction
  extractEmail()

  // Gmail is SPA-driven; route changes need explicit re-check/reset.
  window.addEventListener('hashchange', scheduleExtraction)
  window.addEventListener('popstate', scheduleExtraction)
}

chrome.runtime.onMessage.addListener((message: EmailStateMessage | { type: string; payload?: unknown }) => {
  if (extractorDisabled) return

  if (message.type === 'RESET_EMAIL_STATE') {
    clearEmailState()
    return
  }

  if (message.type === 'EMAIL_STATE_UPDATED') {
    const state = message.payload
    if (!isEmailStatePayload(state) || state.status !== 'ready') {
      clearSubjectHighlight()
      return
    }
    highlightSubject(state.riskScore, state.riskLabel)
  }
})

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeObserver)
} else {
  initializeObserver()
}
