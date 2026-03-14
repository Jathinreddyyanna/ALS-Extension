import type { PageAnalysis } from '../types'

const TRUSTED_BRANDS = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'facebook', 'instagram', 'bank', 'visa', 'mastercard']
const URGENT_PHRASES = [
  'verify your account',
  'account will be suspended',
  'update payment immediately',
  'confirm your password',
  'security alert',
  'urgent action required',
  'payment failed',
  'limited time',
  'verify now',
]

function textContentSample() {
  return (document.body?.innerText || '').toLowerCase().slice(0, 8000)
}

function sameRegisteredBrand(hostname: string, brand: string) {
  const lower = hostname.toLowerCase()
  return lower === brand || lower.endsWith(`.${brand}.com`) || lower.includes(`${brand}.`)
}

function countUrgentTerms(text: string) {
  return URGENT_PHRASES.reduce((count, phrase) => count + (text.includes(phrase) ? 1 : 0), 0)
}

function inspectForms(text: string) {
  const forms = Array.from(document.querySelectorAll('form'))
  let suspiciousForms = 0
  let crossOriginForms = 0
  let hiddenForms = 0

  for (const form of forms) {
    const formText = `${(form.textContent || '').toLowerCase()} ${(form.getAttribute('action') || '').toLowerCase()}`
    const hasSensitiveField = !!form.querySelector('input[type="password"], input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="cvv" i], input[name*="card" i], input[name*="bank" i], input[name*="ssn" i]')
    const asksForSensitiveInfo = /(credit card|card number|bank account|otp|one time password|security code|cvv|pin)/i.test(formText)
    if (hasSensitiveField || asksForSensitiveInfo) suspiciousForms += 1

    try {
      const action = form.getAttribute('action')
      if (action) {
        const actionUrl = new URL(action, window.location.href)
        if (actionUrl.origin !== window.location.origin) crossOriginForms += 1
        if (actionUrl.protocol === 'http:') crossOriginForms += 1
      }
    } catch {}

    const style = window.getComputedStyle(form)
    const isHidden = style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity || '1') === 0
    if (isHidden && (hasSensitiveField || form.querySelector('input[type="password"]'))) hiddenForms += 1
  }

  const loginButtons = document.querySelectorAll('button, a, input[type="submit"]').length
  const loginLikeButtons = Array.from(document.querySelectorAll('button, a, input[type="submit"]')).filter((el) =>
    /(login|sign in|verify|continue|unlock|pay now)/i.test((el.textContent || '') + ' ' + (el.getAttribute('value') || ''))
  ).length

  return {
    suspiciousForms,
    crossOriginForms,
    hiddenForms,
    loginButtons: loginLikeButtons > 0 ? loginLikeButtons : Math.min(loginButtons, 0),
  }
}

function inspectScriptsAndRedirects() {
  const scripts = Array.from(document.scripts)
  const externalScripts = scripts.filter((script) => {
    try {
      return !!script.src && new URL(script.src).origin !== window.location.origin
    } catch {
      return false
    }
  }).length

  let autoRedirects = 0
  if (document.querySelector('meta[http-equiv="refresh" i]')) autoRedirects += 1

  const inlineScriptText = scripts
    .filter((script) => !script.src)
    .map((script) => script.textContent || '')
    .join('\n')
    .toLowerCase()

  if (/(window\.location|location\.href|location\.replace|top\.location)/i.test(inlineScriptText)) autoRedirects += 1

  return { externalScripts, autoRedirects }
}

function inspectBrandMismatch(text: string) {
  const hostname = window.location.hostname.toLowerCase()
  let mismatches = 0
  for (const brand of TRUSTED_BRANDS) {
    if (text.includes(brand) && !sameRegisteredBrand(hostname, brand)) mismatches += 1
  }
  return mismatches
}

export function analyzeCurrentPage(): PageAnalysis {
  const text = textContentSample()
  const urgentTerms = countUrgentTerms(text)
  const { suspiciousForms, crossOriginForms, hiddenForms, loginButtons } = inspectForms(text)
  const { externalScripts, autoRedirects } = inspectScriptsAndRedirects()
  const fakePopups = Array.from(document.querySelectorAll<HTMLElement>('div, section, aside')).filter((el) => {
    const style = window.getComputedStyle(el)
    return style.position === 'fixed' && parseInt(style.zIndex || '0', 10) > 9999
  }).length
  const brandMismatch = inspectBrandMismatch(text)

  const signals: string[] = []
  let score = 0

  if (window.location.protocol !== 'https:') {
    score += 15
    signals.push('Site is not using HTTPS')
  }
  if (urgentTerms > 0) {
    score += Math.min(20, urgentTerms * 8)
    signals.push('Page uses urgent or coercive language')
  }
  if (suspiciousForms > 0) {
    score += Math.min(25, suspiciousForms * 12)
    signals.push('Page asks for passwords, OTP, banking, or card details')
  }
  if (crossOriginForms > 0) {
    score += Math.min(20, crossOriginForms * 10)
    signals.push('Form submits data to a different or insecure destination')
  }
  if (hiddenForms > 0) {
    score += 15
    signals.push('Hidden login or credential forms detected')
  }
  if (brandMismatch > 0) {
    score += Math.min(20, brandMismatch * 10)
    signals.push('Visible brand names do not match the domain')
  }
  if (loginButtons >= 3) {
    score += 10
    signals.push('Too many login or verify buttons on the page')
  }
  if (fakePopups > 0) {
    score += Math.min(15, fakePopups * 8)
    signals.push('Aggressive fixed overlays or fake popups detected')
  }
  if (autoRedirects > 0) {
    score += Math.min(15, autoRedirects * 10)
    signals.push('Automatic redirect behavior detected')
  }
  if (externalScripts >= 12) {
    score += 10
    signals.push('Heavy use of third-party scripts')
  }

  return {
    score: Math.min(100, score),
    signals,
    counts: {
      urgentTerms,
      suspiciousForms,
      crossOriginForms,
      hiddenForms,
      loginButtons,
      fakePopups,
      externalScripts,
      autoRedirects,
    },
  }
}

export function initPageInspector() {
  const runAnalysis = () => {
    if (!document.body) return
    const analysis = analyzeCurrentPage()
    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS',
      payload: {
        url: window.location.href,
        analysis,
      },
    }).catch(() => {})
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    window.setTimeout(runAnalysis, 1200)
  } else {
    document.addEventListener('DOMContentLoaded', () => window.setTimeout(runAnalysis, 1200), { once: true })
  }

  let debounceId: number | null = null
  const observer = new MutationObserver(() => {
    if (debounceId) window.clearTimeout(debounceId)
    debounceId = window.setTimeout(runAnalysis, 1200)
  })

  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: false })
}
