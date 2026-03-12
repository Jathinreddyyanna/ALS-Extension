import { initPopupMonitor } from './popupMonitor'
import { initHoverPreview } from './hoverPreview'
import { injectOverlay, showWarningOverlay, showRedirectWarning, showDownloadWarning } from './overlayInjector'

// Init all content-script features
initPopupMonitor()
initHoverPreview()
injectOverlay()

// Listen for messages from background SW
// Note: overlayInjector sends OPEN_REPORT_FORM and CANCEL_DOWNLOAD *directly* to background
// via chrome.runtime.sendMessage — no relay needed here
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'SHOW_OVERLAY') {
    showWarningOverlay(message.payload)
  }
  if (message.type === 'REDIRECT_WARNING') {
    showRedirectWarning(message.payload)
  }
  if (message.type === 'DOWNLOAD_WARNING') {
    showDownloadWarning(message.payload)
  }
})
