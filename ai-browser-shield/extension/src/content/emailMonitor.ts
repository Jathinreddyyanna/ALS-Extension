declare global {
  interface Window {
    __absEmailMonitorInstalled?: boolean
  }
}

function isGmail() {
  return location.hostname.includes('mail.google.com')
}

function trimAndCleanText(text: string) {
  if (!text) return ''
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join('\n')
    .replace(/\n\n+/g, '\n\n')
}

function injectStyles() {
  if (document.getElementById('abs-email-monitor-styles')) return
  const style = document.createElement('style')
  style.id = 'abs-email-monitor-styles'
  style.textContent = `
    @keyframes absRainbowMove {
      0% { background-position: 0% 50%; }
      100% { background-position: 200% 50%; }
    }

    .abs-email-highlight {
      transition: all 0.5s ease !important;
      box-sizing: border-box !important;
      border-radius: 8px !important;
    }

    .abs-email-processing {
      padding: 6px 10px !important;
      border: 4px solid transparent !important;
      background:
        linear-gradient(white, white) padding-box,
        linear-gradient(90deg, red, orange, yellow, green, blue, violet, red) border-box !important;
      background-size: 200% 200% !important;
      animation: absRainbowMove 3s linear infinite !important;
      color: #333 !important;
    }

    .abs-email-safe {
      background-color: #2ecc40 !important;
      color: #fff !important;
      border: 2px solid #2ecc40 !important;
      animation: none !important;
      padding: 6px 10px !important;
    }

    .abs-email-suspicious {
      background-color: #ffcc00 !important;
      color: #000 !important;
      border: 2px solid #ffcc00 !important;
      animation: none !important;
      padding: 6px 10px !important;
    }

    .abs-email-dangerous {
      background-color: #ff3b3b !important;
      color: #fff !important;
      border: 2px solid #ff3b3b !important;
      animation: none !important;
      padding: 6px 10px !important;
    }
  `
  document.head.appendChild(style)
}

function getSubjectElement() {
  const selectors = [
    'h2.hP',
    'h2[data-subject-threading]',
    'h2[role="heading"]',
    '[data-subject]',
    '.hP',
    '.ha h2',
    'div[role="main"] h2',
  ]

  for (const selector of selectors) {
    const element = document.querySelector<HTMLElement>(selector)
    if (element) return element
  }

  return null
}

function applyHighlight(element: HTMLElement | null, label: string) {
  if (!element) return

  element.classList.add('abs-email-highlight')
  element.classList.remove('abs-email-processing', 'abs-email-safe', 'abs-email-suspicious', 'abs-email-dangerous')
  void element.offsetWidth

  if (label === 'processing') element.classList.add('abs-email-processing')
  if (label === 'safe') element.classList.add('abs-email-safe')
  if (label === 'suspicious') element.classList.add('abs-email-suspicious')
  if (label === 'dangerous' || label === 'scam') element.classList.add('abs-email-dangerous')

  element.setAttribute('data-email-risk-highlight', label)
}

function extractEmailData() {
  const emailData = {
    subject: '',
    from: '',
    fromEmail: '',
    body: '',
    links: [] as string[],
    platform: 'gmail' as const,
  }

  try {
    const subjectEl = getSubjectElement()
    if (subjectEl) emailData.subject = (subjectEl.innerText || '').trim()

    const senderNameEl = document.querySelector<HTMLElement>('.gD')
    if (senderNameEl) {
      emailData.from = senderNameEl.innerText.trim()
      emailData.fromEmail = senderNameEl.getAttribute('email') || senderNameEl.getAttribute('data-hovercard-id') || ''
    }

    const bodyElements = document.querySelectorAll<HTMLElement>('.a3s.aiL, .a3s.ajx, [role="main"] .mGp')
    for (const bodyEl of bodyElements) {
      if (bodyEl.offsetHeight > 0) {
        emailData.body = trimAndCleanText(bodyEl.innerText)
        emailData.links = Array.from(bodyEl.querySelectorAll<HTMLAnchorElement>('a[href]')).map((link) => link.href).filter(Boolean).slice(0, 20)
        break
      }
    }

    if (!emailData.body) {
      const altBody = document.querySelector<HTMLElement>('.msg, .h7')
      if (altBody) {
        emailData.body = trimAndCleanText(altBody.innerText)
        emailData.links = Array.from(altBody.querySelectorAll<HTMLAnchorElement>('a[href]')).map((link) => link.href).filter(Boolean).slice(0, 20)
      }
    }

    if (emailData.body.length > 1500) {
      emailData.body = emailData.body.substring(0, 1500)
    }
  } catch (error) {
    console.error('[EmailMonitor] Extraction failed:', error)
  }

  return emailData
}

export function initEmailMonitor() {
  if (!isGmail() || window.__absEmailMonitorInstalled) return
  window.__absEmailMonitorInstalled = true
  injectStyles()

  let lastSent: string | null = null
  let candidateStr: string | null = null
  let candidateCount = 0
  let lastSubjectText = ''

  chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    if (request.type === 'predictionResult' && request.data) {
      console.log('[EmailMonitor] Received prediction:', request.data)
      const label = request.data.risk_label || request.data.final_risk_label || 'safe'
      chrome.storage.local.set({ currentAnalysis: request.data })
      applyHighlight(getSubjectElement(), label)
      sendResponse({ status: 'received' })
      return true
    }
    return true
  })

  const observer = new MutationObserver(() => {
    const element = getSubjectElement()
    if (!element) return
    const currentText = element.innerText.trim()
    if (currentText !== lastSubjectText && currentText.length > 0) {
      lastSubjectText = currentText
      applyHighlight(element, 'processing')
    }
  })
  observer.observe(document.body, { childList: true, subtree: true, characterData: true })

  window.setInterval(() => {
    const data = extractEmailData()
    if (!(data.body.length > 20 || data.subject.length > 6)) return

    const dataStr = JSON.stringify(data)

    if (data.subject !== lastSubjectText) {
      lastSubjectText = data.subject
      applyHighlight(getSubjectElement(), 'processing')
    }

    if (dataStr === candidateStr) {
      candidateCount += 1
    } else {
      candidateStr = dataStr
      candidateCount = 1
    }

    if (dataStr !== lastSent && candidateCount >= 2) {
      lastSent = dataStr
      console.log('[EmailMonitor] Sending Gmail snapshot:', { subject: data.subject, fromEmail: data.fromEmail, bodyLength: data.body.length })
      chrome.runtime.sendMessage({ action: 'updateEmail', data })
    }
  }, 700)
}
