/**
 * Warning Banner Component - Clean, Collapsible Design
 * Production-ready phishing detection banner for Gmail
 */

import { MLAnalysisResult } from '../api/mlAnalysis';

const BANNER_ID = 'phishing-detection-banner';
const DETAILS_PANEL_ID = 'phishing-details-panel';
const CLOSE_BTN_ID = 'banner-close-btn';
const TOGGLE_BTN_ID = 'banner-toggle-btn';
const REOPEN_CHIP_ID = 'risk-reopen-chip';

// Cache last analysis result so banner can be reopened without API call
let lastAnalysisResult: MLAnalysisResult | null = null;
let closeAnimationTimeoutId: number | null = null;

function clearPendingCloseAnimation(): void {
  if (closeAnimationTimeoutId !== null) {
    window.clearTimeout(closeAnimationTimeoutId);
    closeAnimationTimeoutId = null;
  }
}

export interface RiskColors {
  color: string;
  bgColor: string;
  borderColor: string;
  emoji: string;
}

/**
 * Get color scheme based on risk score
 */
export function getRiskColors(riskScore: number): RiskColors {
  if (riskScore >= 80) {
    return {
      color: '#DC2626',
      bgColor: '#FEE2E2',
      borderColor: '#EF4444',
      emoji: '🚨'
    };
  } else if (riskScore >= 50) {
    return {
      color: '#EA580C',
      bgColor: '#FFEDD5',
      borderColor: '#F97316',
      emoji: '⚠️'
    };
  } else if (riskScore >= 30) {
    return {
      color: '#CA8A04',
      bgColor: '#FEF3C7',
      borderColor: '#EAB308',
      emoji: '⚡'
    };
  } else {
    return {
      color: '#16A34A',
      bgColor: '#D1FAE5',
      borderColor: '#22C55E',
      emoji: '✅'
    };
  }
}

/**
 * Display collapsible warning banner (COLLAPSED by default)
 */
export function displayWarningBanner(result: MLAnalysisResult, loading: boolean = false): void {
  clearPendingCloseAnimation();
  removeWarningBanner();
  // Whenever banner is visible, chip should be hidden.
  removeReopenChip();

  // Store result for reopen without API call
  if (!loading) {
    lastAnalysisResult = result;
    console.log('[Banner] Cached analysis result for reopen');
  }

  const colors = getRiskColors(result.risk_score);
  console.log('[Banner] Rendering banner - Risk: ' + result.risk_score);

  // Add global styles for banner animations
  if (!document.getElementById('banner-styles')) {
    const style = document.createElement('style');
    style.id = 'banner-styles';
    style.textContent = `
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
          opacity: 0;
        }
        to {
          transform: translateY(0);
          opacity: 1;
        }
      }
      @keyframes slideUp {
        from {
          opacity: 1;
        }
        to {
          opacity: 0;
          transform: translateY(-20px);
        }
      }
      @keyframes chipIn {
        from {
          opacity: 0;
          transform: scale(0.92);
        }
        to {
          opacity: 1;
          transform: scale(1);
        }
      }
      .banner-expand {
        animation: slideDown 0.3s ease-out;
      }
      .details-panel {
        max-height: 500px;
        overflow: hidden;
        transition: max-height 0.4s ease-in-out, opacity 0.3s ease-in-out;
        opacity: 1;
      }
      .details-panel.hidden {
        max-height: 0;
        opacity: 0;
      }
    `;
    document.head.appendChild(style);
  }

  // Create banner
  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.className = 'banner-expand';

  if (loading) {
    banner.style.cssText = `
      position: fixed;
      top: 65px;
      left: 0;
      right: 0;
      z-index: 99999;
      background: linear-gradient(135deg, #F3F4F6 0%, #F3F4F6cc 100%);
      border-bottom: 3px solid #D1D5DB;
      padding: 12px 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    `;
    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <div style="font-size: 20px; animation: spin 2s linear infinite;">🔍</div>
        <span style="font-size: 14px; color: #4B5563; font-weight: 500;">Analyzing email...</span>
      </div>
    `;
  } else {
    const summaryLabel = result.risk_score >= 80
      ? 'Phishing Likely'
      : result.risk_score >= 30
        ? 'Suspicious Email'
        : 'Safe Email';

    const summaryReason = ((result.reasons && result.reasons.length > 0)
      ? result.reasons[0]
      : (result.explanation?.reasons && result.explanation.reasons.length > 0)
        ? result.explanation.reasons[0]
        : 'Risk patterns detected by analysis engine').trim();

    banner.style.cssText = `
      position: fixed;
      top: 65px;
      left: 0;
      right: 0;
      z-index: 99999;
      background: ${colors.bgColor};
      border-bottom: 3px solid ${colors.borderColor};
      padding: 12px 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      transition: all 0.3s ease;
    `;

    // COLLAPSED STATE: Minimal header
    const headerHtml = `
      <div style="display: grid; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 12px; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0;">
            <span style="font-size: 28px; line-height: 1;">${colors.emoji}</span>
            <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
              <span style="font-weight: 800; font-size: 14px; color: ${colors.color};">${summaryLabel} (${result.risk_score}/100)</span>
            </div>
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            <button id="${TOGGLE_BTN_ID}" style="
              background: ${colors.color};
              color: white;
              border: none;
              padding: 6px 14px;
              border-radius: 6px;
              font-size: 13px;
              font-weight: 600;
              cursor: pointer;
              white-space: nowrap;
              transition: all 0.2s;
            ">Show Details ▾</button>
            <button id="${CLOSE_BTN_ID}" style="
              background: transparent;
              color: ${colors.color};
              border: none;
              padding: 4px 8px;
              cursor: pointer;
              font-size: 18px;
              font-weight: bold;
              transition: all 0.2s;
              line-height: 1;
            " title="Close banner">✖</button>
          </div>
        </div>
        <div style="font-size: 13px; color: #1F2937; font-weight: 600;">
          Reason: <span style="font-weight: 500;">${summaryReason}</span>
        </div>
      </div>
    `;

    // EXPANDED DETAILS: Hidden by default
    const detailsHtml = `
      <div id="${DETAILS_PANEL_ID}" class="details-panel hidden" style="
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid ${colors.borderColor};
      ">
        ${formatExplanation(result)}
      </div>
    `;

    banner.innerHTML = headerHtml + detailsHtml;
  }

  // Insert banner
  try {
    if (document.documentElement) {
      document.documentElement.insertBefore(banner, document.documentElement.firstChild);
    } else if (document.body) {
      document.body.insertBefore(banner, document.body.firstChild);
    } else {
      return; // Document not ready
    }
    console.log('[Banner] Rendered');
  } catch (error) {
    try {
      if (document.body) {
        document.body.appendChild(banner);
      }
    } catch (fallbackError) {
      console.log('[Banner] Failed to insert:', fallbackError);
    }
  }

  // Attach event listeners
  if (!loading) {
    attachEventListeners(colors);
  }
}

/**
 * Format explanation with 3 sections
 */
function formatExplanation(result: MLAnalysisResult): string {
  const reasons = (result.reasons && result.reasons.length > 0
    ? result.reasons
    : result.explanation?.reasons || []).slice(0, 3);

  const attackType = result.attack_type || 'Unknown Pattern';

  const senderTrustRaw = (result.sender_trust || 'new').toString().toLowerCase();
  const senderTrustLabel = senderTrustRaw === 'flagged'
    ? 'Previously flagged'
    : senderTrustRaw === 'known'
      ? 'Seen before'
      : 'New sender';

  return `
    <div style="display: grid; gap: 14px; font-size: 13px; color: #374151;">
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🚩 Why Flagged:</div>
        <ul style="margin: 0; padding-left: 18px; line-height: 1.6;">
          ${(reasons.length > 0 ? reasons : ['Risk patterns detected by ML model']).map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🎯 Attack Type:</div>
        <div style="padding: 8px 10px; background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; font-weight: 600; color: #111827;">
          ${attackType}
        </div>
      </div>
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🛡️ Sender Trust:</div>
        <div style="padding: 8px 10px; background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; font-weight: 600; color: #111827;">
          ${senderTrustLabel}
        </div>
      </div>
    </div>
  `;
}

/**
 * Create and display reopen chip (allows reopening banner without API call)
 * Places chip inline next to the risk badge near the subject
 */
function createReopenChip(result: MLAnalysisResult): void {
  clearPendingCloseAnimation();
  removeReopenChip(); // Ensure only one chip exists

  console.log('[Chip] Creating chip with result:', result.risk_score);

  const colors = getRiskColors(result.risk_score);
  const chip = document.createElement('button');
  chip.id = REOPEN_CHIP_ID;
  
  // Always-visible fixed positioning so judges can reopen details instantly.
  chip.style.cssText = `
    position: fixed;
    top: 75px;
    right: 12px;
    z-index: 99998;
    padding: 8px 14px;
    background: ${colors.bgColor};
    border: 2px solid ${colors.borderColor};
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
    color: ${colors.color};
    cursor: pointer;
    white-space: nowrap;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 2px 8px rgba(0,0,0,0.12);
    transition: all 0.2s ease;
    animation: chipIn 0.2s ease-out;
  `;
  chip.innerHTML = `${colors.emoji} View Risk Again`;
  chip.title = 'Click to view risk details again';

  // Hover effects
  chip.addEventListener('mouseover', () => {
    chip.style.opacity = '0.95';
    chip.style.transform = 'translateY(-1px)';
    chip.style.boxShadow = '0 4px 12px rgba(0,0,0,0.18)';
  });
  chip.addEventListener('mouseout', () => {
    chip.style.opacity = '1';
    chip.style.transform = 'translateY(0)';
    chip.style.boxShadow = '0 2px 8px rgba(0,0,0,0.12)';
  });

  // Click to reopen banner
  chip.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    lastAnalysisResult = result;
    console.log('[Chip] Reopening banner with chip-cached result:', result.risk_score);
    removeReopenChip();  // Remove chip since we're reopening banner
    displayWarningBanner(result);
    console.log('[Banner] Reopened from chip');
  });

  // Always append to body for stable visibility regardless of Gmail header DOM changes.
  try {
    if (document.body) {
      document.body.appendChild(chip);
      chip.style.display = 'flex';
      chip.style.alignItems = 'center';
      chip.style.gap = '6px';
      console.log('[Chip] Reopen chip created (fixed)');
    }
  } catch (error) {
    console.log('[Chip] Failed to append chip:', error);
  }
}

/**
 * Remove reopen chip
 */
function removeReopenChip(): void {
  const chip = document.getElementById(REOPEN_CHIP_ID);
  if (chip) {
    chip.remove();
  }
}

/**
 * Attach event listeners to banner buttons
 */
function attachEventListeners(colors: RiskColors): void {
  const closeBtn = document.getElementById(CLOSE_BTN_ID);
  const toggleBtn = document.getElementById(TOGGLE_BTN_ID);
  const detailsPanel = document.getElementById(DETAILS_PANEL_ID);

  // Close button
  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const banner = document.getElementById(BANNER_ID);
      if (banner) {
        clearPendingCloseAnimation();
        banner.style.animation = 'slideUp 0.3s ease-in-out';
        closeAnimationTimeoutId = window.setTimeout(() => {
          banner.remove();
          // Create reopen chip after banner is closed
          if (lastAnalysisResult) {
            createReopenChip(lastAnalysisResult);
            console.log('[Banner] Closed - Reopen chip created');
          }
          closeAnimationTimeoutId = null;
        }, 300);
      }
    });

    closeBtn.addEventListener('mouseover', () => {
      closeBtn.style.opacity = '0.8';
      closeBtn.style.transform = 'scale(1.2)';
    });
    closeBtn.addEventListener('mouseout', () => {
      closeBtn.style.opacity = '1';
      closeBtn.style.transform = 'scale(1)';
    });
  }

  // Toggle details
  if (toggleBtn && detailsPanel) {
    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isHidden = detailsPanel.classList.contains('hidden');

      if (isHidden) {
        detailsPanel.classList.remove('hidden');
        toggleBtn.textContent = 'Hide Details ▲';
        console.log('[Banner] Details expanded');
      } else {
        detailsPanel.classList.add('hidden');
        toggleBtn.textContent = 'Show Details ▾';
        console.log('[Banner] Details collapsed');
      }
    });

    toggleBtn.addEventListener('mouseover', () => {
      toggleBtn.style.opacity = '0.9';
    });
    toggleBtn.addEventListener('mouseout', () => {
      toggleBtn.style.opacity = '1';
    });
  }
}

/**
 * Remove banner from DOM
 */
export function removeWarningBanner(): void {
  clearPendingCloseAnimation();
  const banner = document.getElementById(BANNER_ID);
  if (banner) {
    banner.remove();
  }
  // Note: Do NOT remove chip here—it should persist independently
  // until user clicks it or a new analysis replaces it
}

/**
 * Display risk badge next to subject
 */
export function displayRiskBadge(riskScore: number, riskLevel: string): void {
  removeRiskBadge();

  const subject = document.querySelector('h2.hP') as HTMLElement | null;
  if (!subject) {
    return;
  }

  const colors = getRiskColors(riskScore);
  const badge = document.createElement('span');
  badge.id = 'ml-risk-badge';
  badge.style.cssText = `
    display: inline-block;
    margin-left: 10px;
    padding: 3px 10px;
    background: ${colors.bgColor};
    border: 1px solid ${colors.borderColor};
    border-radius: 10px;
    font-size: 12px;
    font-weight: 700;
    color: ${colors.color};
    white-space: nowrap;
  `;
  badge.innerHTML = `${colors.emoji} ${riskScore}/100`;
  badge.title = riskLevel;
  subject.appendChild(badge);
  console.log('[Badge] Displayed');
}

/**
 * Remove risk badge
 */
export function removeRiskBadge(): void {
  const badge = document.getElementById('ml-risk-badge');
  if (badge) {
    badge.remove();
  }
}

/**
 * Show safe email notification (auto-disappears)
 */
export function showSafeBadge(): void {
  removeWarningBanner();
  displayRiskBadge(0, 'SAFE');

  const notification = document.createElement('div');
  notification.id = 'ml-safe-notification';
  notification.style.cssText = `
    position: fixed;
    top: 75px;
    right: 12px;
    z-index: 99998;
    background: #D1FAE5;
    border: 2px solid #22C55E;
    border-radius: 8px;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 600;
    color: #16A34A;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    animation: slideDown 0.3s ease-out;
  `;
  notification.innerHTML = '✅ Email appears safe';

  try {
    if (document.body) {
      document.body.appendChild(notification);
      console.log('[Badge] Safe notification shown');
    }
  } catch (error) {
    console.log('[Badge] Failed to append notification:', error);
    return;
  }

  setTimeout(() => {
    try {
      if (notification && notification.parentElement) {
        notification.style.transition = 'opacity 0.3s';
        notification.style.opacity = '0';
        setTimeout(() => {
          if (notification && notification.parentElement) {
            notification.remove();
          }
        }, 300);
      }
    } catch (error) {
      // Silently ignore removal errors
    }
  }, 3000);
}
