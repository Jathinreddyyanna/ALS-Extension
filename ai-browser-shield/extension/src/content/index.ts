import { initPopupMonitor } from "./popupMonitor";
// import { initHoverPreview } from "./hoverPreview"; // Removed to eliminate urlScorer dependency (not needed for Gmail email detection)
import {
  injectOverlay,
  showWarningOverlay,
  showRedirectWarning,
  showDownloadWarning,
} from "./overlayInjector";

// ============================================
// DISABLED: Old heuristics-based email system
// REASON: Replaced with ML-based mlIntegration
// FILE: emailExtractor.ts (kept for reference)
// ============================================
// import "./emailExtractor";

// ============================================
// ENABLED: New ML-powered email phishing detection
// ============================================
import "./mlIntegration";

// Init all content-script features
initPopupMonitor();
// initHoverPreview(); // Not needed for Gmail email detection
injectOverlay();

// Listen for messages from background SW (only for redirects/downloads, not emails)
// Note: overlayInjector sends OPEN_REPORT_FORM and CANCEL_DOWNLOAD *directly* to background
// via chrome.runtime.sendMessage — no relay needed here
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SHOW_OVERLAY") {
    showWarningOverlay(message.payload);
  }
  if (message.type === "REDIRECT_WARNING") {
    showRedirectWarning(message.payload);
  }
  if (message.type === "DOWNLOAD_WARNING") {
    showDownloadWarning(message.payload);
  }
  // EMAIL_STATE_UPDATED messages are intentionally ignored (old system deprecated)
});
