/**
 * Gmail ML Integration
 * Detects email opens and analyzes with ML backend
 */

import { analyzeEmailML, checkMLBackendHealth } from '../api/mlAnalysis';
import { displayWarningBanner, removeWarningBanner, showSafeBadge, displayRiskBadge, removeRiskBadge } from './warningBanner';

// Tracking state
let lastAnalyzedEmailId: string | null = null;
let isAnalyzing = false;
let backendHealthy = true;
let analysisCache: Record<string, any> = {}; // Cache results per email ID
let lastBannerDisplayTime = 0; // Prevent race condition with DOM changes
let clearUiTimeoutId: number | null = null;
let detectChangeTimeoutId: number | null = null;

function clearPendingUiClear(): void {
  if (clearUiTimeoutId !== null) {
    window.clearTimeout(clearUiTimeoutId);
    clearUiTimeoutId = null;
  }
}

function scheduleDetectEmailChange(delayMs: number = 180): void {
  if (detectChangeTimeoutId !== null) {
    window.clearTimeout(detectChangeTimeoutId);
  }
  detectChangeTimeoutId = window.setTimeout(() => {
    detectChangeTimeoutId = null;
    detectEmailChange();
  }, delayMs);
}

/**
 * Extract email content from Gmail DOM
 */
function extractEmailFromGmail(): {
  text: string;
  sender: string;
  subject: string;
} | null {
  try {
    // Gmail email body
    const emailBody = document.querySelector('.a3s.aiL');

    // Subject line
    const subjectElement = document.querySelector('.hP');

    // Sender info
    const senderElement = document.querySelector('.gD');

    if (!emailBody) {
      console.log('[ML Integration] Email body not found');
      return null;
    }

    // Extract sender email
    let sender = '';
    if (senderElement) {
      sender = senderElement.getAttribute('email') ||
               senderElement.getAttribute('data-hovercard-id') ||
               senderElement.textContent ||
               '';
    }

    // Extract subject
    const subject = subjectElement?.textContent || '';

    // Extract body text (remove HTML, keep plain text)
    const text = emailBody.textContent || '';

    // Validate we have content
    if (!text || text.trim().length < 10) {
      console.log('[ML Integration] Email text too short');
      return null;
    }

    return {
      text: text.trim(),
      sender: sender.trim(),
      subject: subject.trim()
    };

  } catch (error) {
    console.error('[ML Integration] Error extracting email:', error);
    return null;
  }
}

/**
 * Get current email ID from URL
 */
function getCurrentEmailId(): string | null {
  const hash = window.location.hash;

  // Gmail format: #inbox/message-id or #label/message-id
  if (hash.includes('/')) {
    const parts = hash.split('/');
    return parts[parts.length - 1] || null;
  }

  return null;
}

/**
 * Analyze current email with ML backend
 */
async function analyzeCurrentEmail(): Promise<void> {
  // Prevent concurrent analysis
  if (isAnalyzing) {
    console.log('[ML Integration] ⏳ Already analyzing, skipping...');
    return;
  }

  const emailId = getCurrentEmailId();

  // Skip if same email already analyzed
  if (emailId === lastAnalyzedEmailId) {
    console.log('[ML Integration] ℹ️ Email already analyzed (cached)');
    // Show cached badge if it exists
    if (emailId && analysisCache[emailId]) {
      const cached = analysisCache[emailId];
      displayRiskBadge(cached.risk_score, cached.risk_level);
    }
    return;
  }

  // Wait for email to fully load
  await new Promise(resolve => setTimeout(resolve, 800));

  // Extract email data
  const emailData = extractEmailFromGmail();
  const isSpamFolder = window.location.hash.includes('spam') || window.location.href.includes('in:spam');

  if (!emailData) {
    console.log('[ML Integration] ❌ Unable to extract email data');
    removeWarningBanner();
    removeRiskBadge();
    return;
  }

  isAnalyzing = true;
  lastAnalyzedEmailId = emailId;

  console.log('[ML Integration] 📧 Email detected:', {
    emailId: emailId?.substring(0, 10) + '...',
    sender: emailData.sender,
    subject: emailData.subject.substring(0, 50) + '...',
    textLength: emailData.text.length
  });

  try {
    // Show loading state
    console.log('[ML Integration] 🔄 Calling ML API...');
    displayWarningBanner({
      risk_score: 0,
      label: 'unknown',
      risk_level: 'ANALYZING',
      confidence: 0,
      explanation: {
        risk_level: '',
        reasons: [],
        consequences: [],
        actions: []
      }
    }, true);

    // Call ML backend
    const startTime = Date.now();
    const result = await analyzeEmailML({ ...emailData, is_spam: isSpamFolder });
    const duration = Date.now() - startTime;

    console.log('[ML Integration] ✅ API response received:', {
      risk_score: result.risk_score,
      label: result.label,
      risk_level: result.risk_level,
      confidence: result.confidence,
      duration: `${duration}ms`,
      detectedFeatures: result.explanation?.reasons?.length || 0
    });

    // Cache the result
    if (emailId) {
      analysisCache[emailId] = result;
    }

    // ============================================
    // DISPLAY LOGIC: Show badge for ALL emails
    // ============================================
    console.log('[ML Integration] 🎨 Rendering risk badge...');
    displayRiskBadge(result.risk_score, result.risk_level);
    lastBannerDisplayTime = Date.now(); // Prevent race condition

    // Display banner only if suspicious/dangerous, or when analysis is unavailable.
    if (result.label === 'unknown' || result.risk_level === 'UNKNOWN') {
      console.log('[ML Integration] ⚠️ Analysis unavailable - showing caution banner');
      displayWarningBanner(result, false);
    } else if (result.risk_score < 30) {
      // Low risk - show transient safe notification
      console.log('[ML Integration] 🟢 Email is SAFE - showing transient notification');
      showSafeBadge();
    } else {
      // Show full warning banner for suspicious/dangerous
      console.log('[ML Integration] ⚠️ Email is SUSPICIOUS - showing full warning banner');
      displayWarningBanner(result, false);
    }

  } catch (error) {
    console.error('[ML Integration] ❌ Analysis failed:', error);
    removeWarningBanner();
    removeRiskBadge();

  } finally {
    isAnalyzing = false;
  }
}

/**
 * Detect when user opens/switches emails
 */
function detectEmailChange(): void {
  const currentEmailId = getCurrentEmailId();

  // Check if viewing an email (not inbox/compose)
  const isViewingEmail = currentEmailId &&
                         !window.location.hash.includes('compose') &&
                         window.location.hash.includes('/');

  if (isViewingEmail && currentEmailId !== lastAnalyzedEmailId) {
    clearPendingUiClear();
    console.log('[ML Integration] 📨 New email detected:', currentEmailId?.substring(0, 10) + '...');
    analyzeCurrentEmail();
  } else if (!isViewingEmail) {
    // Gmail hash and DOM can briefly flap during thread transitions.
    // Clear only if we are still out of email view after a short stability delay.
    clearPendingUiClear();
    clearUiTimeoutId = window.setTimeout(() => {
      const hash = window.location.hash || '';
      const hasEmailHash = hash.includes('/');
      const hasEmailHeader = Boolean(document.querySelector('h2.hP'));
      const stillViewingEmail = hasEmailHash || hasEmailHeader;
      const timeSinceDisplay = Date.now() - lastBannerDisplayTime;

      if (!stillViewingEmail && timeSinceDisplay > 1200) {
        console.log('[ML Integration] 🚪 Left email view - clearing UI');
        removeWarningBanner();
        removeRiskBadge();
        lastAnalyzedEmailId = null;
      }
      clearUiTimeoutId = null;
    }, 1800);
  }
}

/**
 * Initialize ML integration
 */
async function initMLIntegration(): Promise<void> {
  console.log('[ML Integration] 🚀 Initializing ML-powered email phishing detection...');

  // Check backend health
  backendHealthy = await checkMLBackendHealth();

  if (!backendHealthy) {
    console.warn('[ML Integration] ⚠️ ML backend NOT responding at http://localhost:5000');
    console.warn('[ML Integration] ⚠️ Make sure Flask server is running: python app.py');
    console.warn('[ML Integration] ⚠️ Extension will be DISABLED without backend');
  } else {
    console.log('[ML Integration] ✅ ML backend is HEALTHY at http://localhost:5000');
  }

  // Listen for URL changes (Gmail SPA navigation)
  let lastUrl = window.location.href;

  const urlObserver = new MutationObserver(() => {
    const currentUrl = window.location.href;

    if (currentUrl !== lastUrl) {
      lastUrl = currentUrl;
      scheduleDetectEmailChange();
    }
  });

  // Observe document for navigation changes
  urlObserver.observe(document, {
    subtree: true,
    childList: true
  });

  // Initial check
  scheduleDetectEmailChange(0);

  console.log('[ML Integration] ✅ ML Integration READY - Monitoring Gmail for emails...');
}

/**
 * Check if we're on Gmail
 */
function isGmailPage(): boolean {
  return window.location.hostname === 'mail.google.com';
}

// Auto-initialize on Gmail
if (isGmailPage()) {
  // Wait for Gmail to load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(initMLIntegration, 1000);
    });
  } else {
    setTimeout(initMLIntegration, 1000);
  }
} else {
  console.log('[ML Integration] Not on Gmail, skipping initialization');
}

// Export for manual testing
(window as any).__mlIntegration = {
  analyzeCurrentEmail,
  extractEmailFromGmail,
  checkHealth: checkMLBackendHealth,
  getAnalysisCache: () => analysisCache,
  clearCache: () => { analysisCache = {}; console.log('[ML Integration] Cache cleared'); }
};

console.log('[ML Integration] 📦 Loaded. Available test commands:');
console.log('  __mlIntegration.analyzeCurrentEmail()  // Manually trigger analysis');
console.log('  __mlIntegration.checkHealth()          // Check backend status');
console.log('  __mlIntegration.getAnalysisCache()     // View cached results');
console.log('  __mlIntegration.clearCache()           // Clear analysis cache');
