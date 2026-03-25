export interface ExtractedEmailPayload {
  emailText: string
  senderEmail: string
  subject: string
  links: string[]
  attachmentNames: string[]
  hasAttachments: boolean
  isSpamFolder: boolean
}

const EMAIL_BODY_SELECTORS = [
  '.email-body',
  '.message-body',
  '[data-message-id]',
  '.msg-body',
  '#message-view',
  '.ReadMsgBody',
  '.gmail_quote',
  '[role="article"]',
  '[data-testid="mail-read-pane"]',
  '[data-message-id] [dir="ltr"]',
]

const SENDER_SELECTORS = [
  '[data-hovercard-id]',
  '.sender',
  '.from',
  '[email]',
  'a[href^="mailto:"]',
]

const SUBJECT_SELECTORS = [
  '[data-subject]',
  'h1',
  'h2',
  '[role="heading"]',
  '[title]'
]

const ATTACHMENT_SELECTORS = [
  '[download]',
  '[data-attachment-id]',
  '.attachment',
  '.atta',
  '[aria-label*="attachment" i]'
]

const WEBMAIL_HOST_HINTS = ['mail', 'gmail', 'outlook', 'proton', 'yahoo', 'inbox', 'webmail']
const WEBMAIL_PATH_HINTS = ['inbox', 'mail', 'message', 'compose', 'thread']
const MIN_EMAIL_BODY_LENGTH = 80
const MAX_BODY_CHARS = 12000
const DEBOUNCE_MS = 350

let observer: MutationObserver | null = null
let debounceTimer: number | null = null
let lastFingerprint = ''
let initialized = false

function isExtensionAlive(): boolean {
  try {
    return Boolean(chrome?.runtime?.id)
  } catch {
    return false
  }
}

function safeSendMessage(message: unknown): void {
  if (!isExtensionAlive()) return
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore extension lifecycle errors.
  }
}

function isVisible(element: Element): element is HTMLElement {
  if (!(element instanceof HTMLElement)) return false
  const style = window.getComputedStyle(element)
  const rect = element.getBoundingClientRect()
  return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0
}

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim()
}

function scoreContainer(element: HTMLElement): number {
  const text = normalizeWhitespace(element.innerText || element.textContent || '')
  const links = element.querySelectorAll('a[href]').length
  const blocks = element.querySelectorAll('p, div, span, br').length
  return text.length + (links * 15) + Math.min(200, blocks * 2)
}

function findMainContainers(): HTMLElement[] {
  const candidates = Array.from(document.querySelectorAll('main, article, [role="main"], [role="article"]'))
    .filter(isVisible)

  if (candidates.length > 0) {
    return candidates
  }

  return [document.body].filter((item): item is HTMLElement => item instanceof HTMLElement)
}

function findMessageContainer(): HTMLElement | null {
  const directMatches = Array.from(document.querySelectorAll(EMAIL_BODY_SELECTORS.join(',')))
    .filter(isVisible)

  if (directMatches.length > 0) {
    return directMatches.sort((left, right) => scoreContainer(right) - scoreContainer(left))[0] ?? null
  }

  const mainContainers = findMainContainers()
  const blocks = mainContainers.flatMap((container) =>
    Array.from(container.querySelectorAll('section, article, div'))
      .filter(isVisible)
      .filter((element) => normalizeWhitespace(element.textContent || '').length >= MIN_EMAIL_BODY_LENGTH)
  )

  if (blocks.length === 0) {
    return mainContainers[0] ?? null
  }

  return blocks.sort((left, right) => scoreContainer(right) - scoreContainer(left))[0] ?? null
}

function extractSender(container: HTMLElement): string {
  for (const selector of SENDER_SELECTORS) {
    const candidate = container.querySelector(selector) ?? document.querySelector(selector)
    if (!(candidate instanceof HTMLElement)) continue
    const mailto = candidate.getAttribute('href')
    if (mailto?.startsWith('mailto:')) {
      return mailto.replace(/^mailto:/i, '').trim()
    }
    const emailAttr = candidate.getAttribute('email') || candidate.getAttribute('data-hovercard-id')
    const text = normalizeWhitespace(emailAttr || candidate.textContent || '')
    const emailMatch = text.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/)
    if (emailMatch) return emailMatch[0]
  }

  const scopedMatch = normalizeWhitespace(container.innerText || '').match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/)
  return scopedMatch ? scopedMatch[0] : ''
}

function extractSubject(container: HTMLElement): string {
  for (const selector of SUBJECT_SELECTORS) {
    const matches = Array.from(document.querySelectorAll(selector)).filter(isVisible)
    for (const match of matches) {
      const text = normalizeWhitespace(
        match.getAttribute('data-subject') ||
        match.getAttribute('title') ||
        match.textContent ||
        ''
      )
      if (text.length >= 3 && text.length <= 240) {
        return text
      }
    }
  }

  const lines = normalizeWhitespace(container.innerText || '').split(/(?<=[.?!])\s+/)
  return lines[0]?.slice(0, 140) ?? ''
}

function extractLinks(container: HTMLElement): string[] {
  const urls = new Set<string>()
  for (const anchor of Array.from(container.querySelectorAll('a[href]'))) {
    const href = anchor.getAttribute('href')
    if (!href) continue
    if (/^https?:\/\//i.test(href)) {
      urls.add(href)
    }
  }

  const bodyMatches = (container.innerText || '').match(/https?:\/\/[^\s<>"']+/gi) ?? []
  for (const match of bodyMatches) {
    urls.add(match)
  }

  return Array.from(urls).slice(0, 20)
}

function extractAttachmentNames(container: HTMLElement): string[] {
  const names = new Set<string>()
  for (const selector of ATTACHMENT_SELECTORS) {
    for (const element of Array.from(document.querySelectorAll(selector)).filter(isVisible)) {
      const label = normalizeWhitespace(
        element.getAttribute('download') ||
        element.getAttribute('aria-label') ||
        element.textContent ||
        ''
      )
      if (label.length >= 2) {
        names.add(label.slice(0, 120))
      }
    }
  }

  for (const element of Array.from(container.querySelectorAll('a[href], button')).filter(isVisible)) {
    const label = normalizeWhitespace(element.textContent || '')
    if (/\.(pdf|docx?|xlsx?|zip|rar|exe|js|html?)$/i.test(label)) {
      names.add(label.slice(0, 120))
    }
  }

  return Array.from(names).slice(0, 10)
}

function buildPayload(): ExtractedEmailPayload | null {
  const container = findMessageContainer()
  if (!container) return null

  const emailText = normalizeWhitespace(container.innerText || container.textContent || '').slice(0, MAX_BODY_CHARS)
  if (emailText.length < MIN_EMAIL_BODY_LENGTH) return null

  const senderEmail = extractSender(container)
  const subject = extractSubject(container)
  const links = extractLinks(container)
  const attachmentNames = extractAttachmentNames(container)
  const hasAttachments = attachmentNames.length > 0
  const isSpamFolder = /spam|junk/i.test(window.location.href) || /spam|junk/i.test(document.body.innerText.slice(0, 400))

  return {
    emailText,
    senderEmail,
    subject,
    links,
    attachmentNames,
    hasAttachments,
    isSpamFolder,
  }
}

function isLikelyWebmail(): boolean {
  const hostname = window.location.hostname.toLowerCase()
  const pathname = window.location.pathname.toLowerCase()
  const bodyText = document.body?.innerText?.slice(0, 800).toLowerCase() ?? ''

  if (WEBMAIL_HOST_HINTS.some((hint) => hostname.includes(hint))) return true
  if (WEBMAIL_PATH_HINTS.some((hint) => pathname.includes(hint))) return true
  if (/compose|inbox|reply|forward|message|from:|subject:/i.test(bodyText)) return true
  if (document.querySelector('[data-message-id], a[href^="mailto:"], [role="main"]')) return true
  return false
}

function scheduleExtraction(): void {
  if (debounceTimer !== null) {
    window.clearTimeout(debounceTimer)
  }
  debounceTimer = window.setTimeout(() => {
    const payload = buildPayload()
    const fingerprint = payload
      ? `${window.location.href}::${payload.senderEmail}::${payload.subject}::${payload.emailText.slice(0, 180)}`
      : ''

    if (!payload) {
      if (lastFingerprint) {
        lastFingerprint = ''
        safeSendMessage({ type: 'RESET_EMAIL_STATE' })
      }
      return
    }

    if (fingerprint === lastFingerprint) return
    lastFingerprint = fingerprint
    safeSendMessage({ type: 'EMAIL_CONTENT', payload })
  }, DEBOUNCE_MS)
}

export function initEmailExtractor(): void {
  if (initialized) return
  initialized = true

  const start = () => {
    if (!isLikelyWebmail()) return
    observer?.disconnect()
    observer = new MutationObserver(() => {
      scheduleExtraction()
    })
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    })
    window.addEventListener('hashchange', scheduleExtraction)
    window.addEventListener('popstate', scheduleExtraction)
    scheduleExtraction()
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true })
  } else {
    start()
  }
}
