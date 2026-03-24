export interface InteractionSignals {
  hiddenIframes?: number
  overlayTrap?: number
  fakePlayButtons?: number
  clickInterception?: number
  popupFrequency?: number
  suspiciousFormCount?: number
  autoSubmitForms?: number
  passwordFieldCount?: number
  creditCardFieldCount?: number
}

export function collectInteractionSignals(): InteractionSignals {
  const signals: InteractionSignals = {}

  try {
    const iframes = document.querySelectorAll('iframe')
    let hiddenIframeCount = 0
    iframes.forEach((iframe) => {
      const rect = iframe.getBoundingClientRect()
      const style = window.getComputedStyle(iframe)
      if (
        rect.width === 0 || rect.height === 0 ||
        style.opacity === '0' ||
        style.visibility === 'hidden' ||
        style.display === 'none'
      ) {
        hiddenIframeCount++
      }
    })
    if (hiddenIframeCount > 0) signals.hiddenIframes = hiddenIframeCount

    const allElements = document.querySelectorAll('*')
    let overlayCount = 0
    allElements.forEach((element) => {
      const style = window.getComputedStyle(element)
      const rect = element.getBoundingClientRect()
      if (
        (style.position === 'fixed' || style.position === 'absolute') &&
        Number.parseInt(style.zIndex || '0', 10) > 999 &&
        rect.width > window.innerWidth * 0.75 &&
        rect.height > window.innerHeight * 0.75
      ) {
        overlayCount++
      }
    })
    if (overlayCount > 0) signals.overlayTrap = overlayCount

    const fakeButtons = document.querySelectorAll(
      'a[href="#"], a[href="javascript:void(0)"], button:not([type="submit"]):not([type="button"])'
    )
    if (fakeButtons.length > 8) {
      signals.fakePlayButtons = fakeButtons.length
    }

    const passwordInputs = document.querySelectorAll('input[type="password"]')
    if (passwordInputs.length > 0) {
      signals.passwordFieldCount = passwordInputs.length
    }
    if (passwordInputs.length > 0) {
      const isOnLoginPath = /login|signin|auth|account|verify|secure/i.test(window.location.pathname)
      if (!isOnLoginPath) {
        signals.suspiciousFormCount = passwordInputs.length
      }
    }

    const cardInputs = document.querySelectorAll<HTMLInputElement>(
      'input[autocomplete="cc-number"], input[name*="card" i], input[id*="card" i], input[placeholder*="card" i]'
    )
    let creditCardFields = cardInputs.length
    if (creditCardFields === 0) {
      const numericInputs = Array.from(document.querySelectorAll<HTMLInputElement>('input[type="text"], input[type="tel"], input:not([type])'))
      creditCardFields = numericInputs.filter((input) => {
        const hint = [input.name, input.id, input.placeholder, input.autocomplete].filter(Boolean).join(' ').toLowerCase()
        return /card|credit|visa|mastercard|amex|payment/.test(hint)
      }).length
    }
    if (creditCardFields > 0) {
      signals.creditCardFieldCount = creditCardFields
    }

    const forms = document.querySelectorAll('form')
    let autoSubmitCount = 0
    forms.forEach((form) => {
      const onsubmit = form.getAttribute('onsubmit') ?? ''
      if (onsubmit.includes('submit()') || onsubmit.includes('auto')) {
        autoSubmitCount++
      }
    })
    if (autoSubmitCount > 0) signals.autoSubmitForms = autoSubmitCount
  } catch {
    // Never break the page because of signal collection.
  }

  return signals
}
