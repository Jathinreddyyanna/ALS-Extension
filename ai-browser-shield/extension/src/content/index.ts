import { initPopupMonitor } from './popupMonitor'
import { initHoverPreview } from './hoverPreview'
import { injectOverlay, showWarningOverlay, showRedirectWarning, showDownloadWarning } from './overlayInjector'
import { extractPageContext } from './pageContext'
import { initEmailMonitor } from './emailMonitor'

// Init all content-script features
initPopupMonitor()
initHoverPreview()
initEmailMonitor()
injectOverlay()

// Listen for messages from background SW
// Note: overlayInjector sends OPEN_REPORT_FORM and CANCEL_DOWNLOAD *directly* to background
// via chrome.runtime.sendMessage — no relay needed here
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'GET_PAGE_CONTEXT') {
    sendResponse(extractPageContext())
    return true
  }
  if (message.type === 'SHOW_OVERLAY') {
    showWarningOverlay(message.payload)
  }
  if (message.type === 'REDIRECT_WARNING') {
    showRedirectWarning(message.payload)
  }
  if (message.type === 'DOWNLOAD_WARNING') {
    showDownloadWarning(message.payload)
  }
  return false
})
