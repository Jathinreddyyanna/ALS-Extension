/**
 * Warning Banner Component - Clean, Collapsible Design
 * Production-ready phishing detection banner for Gmail
 */

import { MLAnalysisResult } from "../api/mlAnalysis";

const BANNER_ID = "phishing-detection-banner";
const DETAILS_PANEL_ID = "phishing-details-panel";
const CLOSE_BTN_ID = "banner-close-btn";
const TOGGLE_BTN_ID = "banner-toggle-btn";
const REOPEN_CHIP_ID = "risk-reopen-chip";

// ============================================
// LINK HIGHLIGHTING SYSTEM
// ============================================

interface LinkRisk {
  url: string;
  risk: 'safe' | 'suspicious' | 'dangerous';
  reason: string;
}

/**
 * URL regex pattern - matches http, https, www, and plain domains
 */
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|xyz|tk|ml|ga|cf|top|click|link|info|biz|co|in)\b[^\s<>"'{}|\\^`\[\]]*/gi;

/**
 * Escape HTML to prevent XSS attacks
 */
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Classify a URL's risk level
 */
function classifyLinkRisk(url: string, backendLinkRisk?: string): LinkRisk {
  const urlLower = url.toLowerCase();

  // If backend provides risk level, use it (future-proof)
  if (backendLinkRisk) {
    return {
      url,
      risk: backendLinkRisk as 'safe' | 'suspicious' | 'dangerous',
      reason: 'Backend analysis'
    };
  }

  // 1. IP ADDRESS CHECK (dangerous)
  const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipPattern.test(urlLower)) {
    return { url, risk: 'dangerous', reason: 'Contains IP address' };
  }

  // 2. SUSPICIOUS TLD CHECK
  const dangerousTlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.link'];
  if (dangerousTlds.some(tld => urlLower.includes(tld))) {
    return { url, risk: 'dangerous', reason: 'Suspicious domain extension' };
  }

  // 3. SHORTENED URL CHECK (with whitelist for legitimate services)
  const legitimateShorteners = ['t.co/', 'youtu.be/', 'amzn.to/', 'ift.tt/', 'bit.do/', 'us.to/'];
  const suspiciousShorteners = ['bit.ly', 'tinyurl.', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link', 'tiny.cc'];

  if (suspiciousShorteners.some(s => urlLower.includes(s))) {
    return { url, risk: 'suspicious', reason: 'Shortened URL hides destination' };
  }
  if (legitimateShorteners.some(s => urlLower.includes(s))) {
    return { url, risk: 'safe', reason: 'Legitimate URL shortener' };
  }

  // 4. TRUSTED PLATFORMS (Pinterest, Instagram, etc.)
  const trustedDomains = ['pinterest.com', 'instagram.com', 'facebook.com', 'twitter.com', 'youtube.com',
                          'amazon.com', 'linkedin.com', 'github.com', 'medium.com'];
  if (trustedDomains.some(domain => urlLower.includes(domain))) {
    return { url, risk: 'safe', reason: 'Trusted social/content platform' };
  }

  // 5. SUSPICIOUS KEYWORDS CHECK
  const suspiciousKeywords = ['login', 'verify', 'update', 'bank', 'secure', 'account',
                              'password', 'confirm', 'suspend', 'locked', 'urgent'];
  if (suspiciousKeywords.some(kw => urlLower.includes(kw))) {
    return { url, risk: 'suspicious', reason: 'Contains sensitive keywords' };
  }

  // 6. LOOKALIKE DOMAIN CHECK (numbers in domain)
  const domainMatch = urlLower.match(/(?:https?:\/\/)?([^\/]+)/);
  if (domainMatch) {
    const domain = domainMatch[1];
    // Check for lookalike patterns (amaz0n, g00gle, etc.)
    if (/[a-z]+\d+[a-z]*\.|\d+[a-z]+\d*\./.test(domain)) {
      return { url, risk: 'dangerous', reason: 'Lookalike domain detected' };
    }
  }

  // 7. HTTPS CHECK (safer but not guaranteed)
  if (urlLower.startsWith('https://')) {
    return { url, risk: 'safe', reason: 'HTTPS encrypted connection' };
  }

  // 8. HTTP without HTTPS
  if (urlLower.startsWith('http://')) {
    return { url, risk: 'suspicious', reason: 'Unencrypted HTTP connection' };
  }

  // Default: suspicious for unknown patterns
  return { url, risk: 'suspicious', reason: 'Unknown link pattern' };
}

/**
 * Get CSS class for link risk level
 */
function getLinkRiskClass(risk: 'safe' | 'suspicious' | 'dangerous'): string {
  switch (risk) {
    case 'safe': return 'link-safe';
    case 'suspicious': return 'link-suspicious';
    case 'dangerous': return 'link-danger';
    default: return 'link-suspicious';
  }
}

/**
 * Get inline styles for link risk level (fallback if CSS classes not loaded)
 */
function getLinkRiskStyle(risk: 'safe' | 'suspicious' | 'dangerous'): string {
  const baseStyle = 'display: inline; padding: 2px 6px; border-radius: 4px; text-decoration: none; word-break: break-all;';
  switch (risk) {
    case 'safe':
      return `${baseStyle} border: 2px solid #22C55E; background: #D1FAE5; color: #166534;`;
    case 'suspicious':
      return `${baseStyle} border: 2px solid #F97316; background: #FFEDD5; color: #9A3412;`;
    case 'dangerous':
      return `${baseStyle} border: 2px solid #EF4444; background: #FEE2E2; color: #991B1B;`;
    default:
      return `${baseStyle} border: 2px solid #F97316; background: #FFEDD5; color: #9A3412;`;
  }
}

/**
 * Get emoji for link risk level
 */
function getLinkRiskEmoji(risk: 'safe' | 'suspicious' | 'dangerous'): string {
  switch (risk) {
    case 'safe': return '✅';
    case 'suspicious': return '⚠️';
    case 'dangerous': return '🚨';
    default: return '⚠️';
  }
}

/**
 * Highlight all links in content with risk-based styling
 * @param content - The text or HTML content to process
 * @param backendLinkAnalysis - Optional backend link analysis data
 * @returns HTML string with highlighted links
 */
export function highlightLinks(content: string, backendLinkAnalysis?: Array<{url: string; risk: string}>): string {
  if (!content) return '';

  // First, escape the content to prevent XSS
  const escapedContent = escapeHtml(content);

  // Find all URLs
  const urlMatches = escapedContent.match(URL_REGEX);
  if (!urlMatches || urlMatches.length === 0) {
    return escapedContent;
  }

  // Deduplicate URLs
  const uniqueUrls = [...new Set(urlMatches)];

  // Build a map of backend analysis if available
  const backendRiskMap = new Map<string, string>();
  if (backendLinkAnalysis) {
    backendLinkAnalysis.forEach(item => {
      backendRiskMap.set(item.url.toLowerCase(), item.risk);
    });
  }

  // Process each URL
  let result = escapedContent;
  for (const url of uniqueUrls) {
    const backendRisk = backendRiskMap.get(url.toLowerCase());
    const linkRisk = classifyLinkRisk(url, backendRisk);
    const riskClass = getLinkRiskClass(linkRisk.risk);
    const riskStyle = getLinkRiskStyle(linkRisk.risk);
    const emoji = getLinkRiskEmoji(linkRisk.risk);

    // Create highlighted link HTML
    const highlightedLink = `<span class="${riskClass}" style="${riskStyle}" title="${linkRisk.reason}">${emoji} ${escapeHtml(url)}</span>`;

    // Replace URL with highlighted version (use word boundary to avoid partial replacements)
    const urlEscaped = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(urlEscaped, 'g'), highlightedLink);
  }

  return result;
}

/**
 * Extract and analyze all links from email content
 * Returns array of link analysis results
 */
export function analyzeEmailLinks(content: string): LinkRisk[] {
  if (!content) return [];

  const urlMatches = content.match(URL_REGEX);
  if (!urlMatches || urlMatches.length === 0) {
    return [];
  }

  // Deduplicate and analyze each URL
  const uniqueUrls = [...new Set(urlMatches)];
  return uniqueUrls.map(url => classifyLinkRisk(url));
}

/**
 * Highlight links directly in the Gmail email body DOM
 * Finds and styles both plain text URLs and <a> tag hrefs
 */
export function highlightLinksInEmailBody(backendLinkAnalysis?: Array<{url: string; risk: string}>): void {
  // Find Gmail email body
  const emailBody = document.querySelector('.a3s.aiL') as HTMLElement;
  if (!emailBody) {
    console.log('[Link Highlighter] Email body not found');
    return;
  }

  // Inject CSS styles if not already present
  if (!document.getElementById('link-highlight-styles')) {
    const styleEl = document.createElement('style');
    styleEl.id = 'link-highlight-styles';
    styleEl.textContent = getLinkHighlightStyles();
    document.head.appendChild(styleEl);
  }

  // Build backend risk map
  const backendRiskMap = new Map<string, string>();
  if (backendLinkAnalysis) {
    backendLinkAnalysis.forEach(item => {
      backendRiskMap.set(item.url.toLowerCase(), item.risk.toLowerCase());
    });
  }

  // Process all text nodes and anchor tags to find and highlight URLs
  const walker = document.createTreeWalker(
    emailBody,
    NodeFilter.SHOW_TEXT,
    null,
    false
  );

  const nodesToReplace: { node: Node; parent: HTMLElement; html: string }[] = [];
  let textNode: Node | null;

  while ((textNode = walker.nextNode())) {
    const text = textNode.textContent;
    if (!text) continue;

    // Find URLs in this text node
    const urlMatches = text.match(URL_REGEX);
    if (urlMatches && urlMatches.length > 0) {
      // We found URLs, prepare to replace this text node with highlighted HTML
      const uniqueUrls = [...new Set(urlMatches)];
      let highlightedText = escapeHtml(text);

      // Replace each URL with highlighted version
      for (const url of uniqueUrls) {
        const backendRisk = backendRiskMap.get(url.toLowerCase());
        const linkRisk = classifyLinkRisk(url, backendRisk);
        const riskStyle = getLinkRiskStyle(linkRisk.risk);
        const emoji = getLinkRiskEmoji(linkRisk.risk);

        // Create highlighted link HTML
        const highlightedLink = `<span class="link-highlight-${linkRisk.risk}" style="${riskStyle}" title="${linkRisk.reason}">${emoji} ${escapeHtml(url)}</span>`;

        // Replace URL with highlighted version
        const urlEscaped = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        highlightedText = highlightedText.replace(new RegExp(urlEscaped, 'g'), highlightedLink);
      }

      // Store for later replacement (to avoid modifying DOM while iterating)
      const parent = textNode.parentElement;
      if (parent) {
        nodesToReplace.push({
          node: textNode,
          parent: parent,
          html: highlightedText
        });
      }
    }
  }

  // Now replace text nodes with highlighted HTML
  nodesToReplace.forEach(({ node, parent, html }) => {
    const span = document.createElement('span');
    span.innerHTML = html;
    parent.replaceChild(span, node);
  });

  // Also handle existing <a> tags
  const links = emailBody.querySelectorAll('a');
  links.forEach(link => {
    const href = link.getAttribute('href') || '';
    const backendRisk = backendRiskMap.get(href.toLowerCase());

    if (href && (backendRisk || href.includes('http'))) {
      const linkRisk = classifyLinkRisk(href, backendRisk);
      link.className = `link-highlight-${linkRisk.risk}`;
      link.style.cssText = getLinkRiskStyle(linkRisk.risk);
      link.title = linkRisk.reason;

      // Add emoji prefix if not already there
      if (!link.textContent?.includes(getLinkRiskEmoji(linkRisk.risk))) {
        const emoji = document.createTextNode(getLinkRiskEmoji(linkRisk.risk) + ' ');
        link.insertBefore(emoji, link.firstChild);
      }
    }
  });

  console.log('[Link Highlighter] Email body links highlighted successfully');
}

/**
 * Generate CSS for link highlighting (to be injected into page)
 */
function getLinkHighlightStyles(): string {
  return `
    .link-safe {
      display: inline;
      padding: 2px 6px;
      border: 2px solid #22C55E;
      border-radius: 4px;
      background: #D1FAE5;
      color: #166534;
      text-decoration: none;
      word-break: break-all;
      font-weight: 500;
    }
    .link-suspicious {
      display: inline;
      padding: 2px 6px;
      border: 2px solid #F97316;
      border-radius: 4px;
      background: #FFEDD5;
      color: #9A3412;
      text-decoration: none;
      word-break: break-all;
      font-weight: 500;
    }
    .link-danger {
      display: inline;
      padding: 2px 6px;
      border: 2px solid #EF4444;
      border-radius: 4px;
      background: #FEE2E2;
      color: #991B1B;
      text-decoration: none;
      word-break: break-all;
      font-weight: 600;
    }
    .link-safe:hover, .link-suspicious:hover, .link-danger:hover {
      opacity: 0.85;
      cursor: help;
    }
  `;
}

// Cache last analysis result so banner can be reopened without API call
let lastAnalysisResult: MLAnalysisResult | null = null;
let closeAnimationTimeoutId: number | null = null;
let chipObserver: MutationObserver | null = null;

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
 * Dynamically detect Gmail header height to position banner correctly
 */
function getGmailHeaderHeight(): number {
  const selectors = ["div.gb_nd", "header", ".G-atb", 'div[gh="mtb"]'];

  let maxBottom = 0;
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el) {
      const rect = el.getBoundingClientRect();
      if (rect.bottom > maxBottom) {
        maxBottom = rect.bottom;
      }
    }
  }

  return maxBottom > 0 ? maxBottom : 0;
}

/**
 * Get color scheme based on risk score
 */
export function getRiskColors(riskScore: number): RiskColors {
  if (riskScore >= 80) {
    return {
      color: "#DC2626",
      bgColor: "#FEE2E2",
      borderColor: "#EF4444",
      emoji: "🚨",
    };
  } else if (riskScore >= 50) {
    return {
      color: "#EA580C",
      bgColor: "#FFEDD5",
      borderColor: "#F97316",
      emoji: "⚠️",
    };
  } else if (riskScore >= 30) {
    return {
      color: "#CA8A04",
      bgColor: "#FEF3C7",
      borderColor: "#EAB308",
      emoji: "⚡",
    };
  } else {
    return {
      color: "#16A34A",
      bgColor: "#D1FAE5",
      borderColor: "#22C55E",
      emoji: "✅",
    };
  }
}

/**
 * Display collapsible warning banner (COLLAPSED by default)
 */
export function displayWarningBanner(
  result: MLAnalysisResult,
  loading: boolean = false,
): void {
  clearPendingCloseAnimation();
  removeWarningBanner();
  // Whenever banner is visible, chip should be hidden.
  removeReopenChip();

  // Store result for reopen without API call
  if (!loading) {
    lastAnalysisResult = result;
    console.log("[Banner] Cached analysis result for reopen");
  }

  const colors = getRiskColors(result.risk_score);
  const topOffset = getGmailHeaderHeight();
  console.log(
    "[Banner] Rendering banner - Risk: " +
      result.risk_score +
      " topOffset: " +
      topOffset,
  );

  // Add global styles for banner animations
  if (!document.getElementById("banner-styles")) {
    const style = document.createElement("style");
    style.id = "banner-styles";
    style.textContent = `
      @keyframes spin {
        from {
          transform: rotate(0deg);
        }
        to {
          transform: rotate(360deg);
        }
      }
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
      .phish-chip-enter {
        animation: chipIn 0.2s ease-out forwards;
      }
      .phish-loading-spinner {
        animation: spin 2s linear infinite;
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
      /* Link Highlighting Styles */
      .link-safe {
        display: inline;
        padding: 2px 6px;
        border: 2px solid #22C55E;
        border-radius: 4px;
        background: #D1FAE5;
        color: #166534;
        text-decoration: none;
        word-break: break-all;
        font-weight: 500;
        font-size: 12px;
      }
      .link-suspicious {
        display: inline;
        padding: 2px 6px;
        border: 2px solid #F97316;
        border-radius: 4px;
        background: #FFEDD5;
        color: #9A3412;
        text-decoration: none;
        word-break: break-all;
        font-weight: 500;
        font-size: 12px;
      }
      .link-danger {
        display: inline;
        padding: 2px 6px;
        border: 2px solid #EF4444;
        border-radius: 4px;
        background: #FEE2E2;
        color: #991B1B;
        text-decoration: none;
        word-break: break-all;
        font-weight: 600;
        font-size: 12px;
      }
      .link-safe:hover, .link-suspicious:hover, .link-danger:hover {
        opacity: 0.85;
        cursor: help;
      }
      .links-section {
        margin-top: 10px;
        padding: 10px;
        background: #F9FAFB;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
      }
      .links-section-title {
        font-weight: 700;
        font-size: 13px;
        margin-bottom: 8px;
        color: #111827;
      }
      .link-item {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        margin-bottom: 6px;
        font-size: 12px;
      }
      .link-item:last-child {
        margin-bottom: 0;
      }
    `;
    try {
      if (document.head) {
        document.head.appendChild(style);
      } else if (document.documentElement) {
        document.documentElement.appendChild(style);
      }
    } catch (e) {
      console.log("[Banner] Failed to insert styles:", e);
    }
  }

  // Create banner
  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.className = "banner-expand";

  if (loading) {
    banner.style.cssText = `
      position: fixed;
      top: ${topOffset}px;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #F3F4F6 0%, #F3F4F6cc 100%);
      border-bottom: 3px solid #D1D5DB;
      padding: 12px 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    `;
    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <div class="phish-loading-spinner" style="font-size: 20px;">🔍</div>
        <span style="font-size: 14px; color: #4B5563; font-weight: 500;">Analyzing email...</span>
      </div>
    `;
  } else {
    const summaryLabel =
      result.risk_score >= 80
        ? "Phishing Likely"
        : result.risk_score >= 30
          ? "Suspicious Email"
          : "Safe Email";

    const summaryReason = (
      result.reasons && result.reasons.length > 0
        ? result.reasons[0]
        : result.explanation?.reasons && result.explanation.reasons.length > 0
          ? result.explanation.reasons[0]
          : "Risk patterns detected by analysis engine"
    ).trim();

    banner.style.cssText = `
      position: fixed;
      top: ${topOffset}px;
      left: 0;
      right: 0;
      z-index: 2147483647;
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

  // Insert banner into body (NOT documentElement — avoids head/positioning issues)
  try {
    if (document.body) {
      document.body.insertBefore(banner, document.body.firstChild);
      console.log("[Banner] Rendered into body - ID:", banner.id, "Classes:", banner.className);
      console.log("[Banner] Display:", window.getComputedStyle(banner).display);
    } else {
      console.log("[Banner] document.body not available yet");
    }
  } catch (error) {
    console.log("[Banner] insertBefore failed, trying appendChild:", error);
    try {
      if (document.body) {
        document.body.appendChild(banner);
        console.log("[Banner] Appended to body (fallback)");
      }
    } catch (fallbackError) {
      console.log("[Banner] Failed to insert:", fallbackError);
    }
  }

  // Attach event listeners
  if (!loading) {
    attachEventListeners(colors);
  }
}

/**
 * Format explanation with 4 sections (including link analysis)
 */
function formatExplanation(result: MLAnalysisResult): string {
  const reasons = (
    result.reasons && result.reasons.length > 0
      ? result.reasons
      : result.explanation?.reasons || []
  ).slice(0, 3);

  const attackType = result.attack_type || "Unknown Pattern";

  const senderTrustRaw = (result.sender_trust || "new")
    .toString()
    .toLowerCase();
  const senderTrustLabel =
    senderTrustRaw === "suspicious"
      ? "⚠️ Suspicious sender"
      : senderTrustRaw === "trusted"
        ? "✅ Trusted sender"
        : senderTrustRaw === "known"
          ? "👤 Known sender"
          : "🆕 New sender";

  // Generate link analysis section from backend data
  let linksSection = '';
  const linkAnalysis = result.link_analysis || [];

  if (linkAnalysis.length > 0) {
    const linkItems = linkAnalysis.slice(0, 5).map(link => {
      const riskClass = link.risk === 'dangerous' ? 'link-danger' :
                        link.risk === 'suspicious' ? 'link-suspicious' : 'link-safe';
      const emoji = link.risk === 'dangerous' ? '🚨' :
                    link.risk === 'suspicious' ? '⚠️' : '✅';
      // Truncate long URLs for display
      const displayUrl = link.url.length > 50 ? link.url.slice(0, 47) + '...' : link.url;

      return `
        <div class="link-item">
          <span class="${riskClass}" title="${escapeHtml(link.url)}\n${escapeHtml(link.reason)}">
            ${emoji} ${escapeHtml(displayUrl)}
          </span>
          <span style="color: #6B7280; font-size: 11px;">${escapeHtml(link.reason)}</span>
        </div>
      `;
    }).join('');

    linksSection = `
      <div class="links-section">
        <div class="links-section-title">🔗 Links Detected (${linkAnalysis.length}):</div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          ${linkItems}
        </div>
      </div>
    `;
  }

  return `
    <div style="display: grid; gap: 14px; font-size: 13px; color: #374151;">
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🚩 Why Flagged:</div>
        <ul style="margin: 0; padding-left: 18px; line-height: 1.6;">
          ${(reasons.length > 0 ? reasons : ["Risk patterns detected by ML model"]).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>
      </div>
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🎯 Attack Type:</div>
        <div style="padding: 8px 10px; background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; font-weight: 600; color: #111827;">
          ${escapeHtml(attackType)}
        </div>
      </div>
      <div>
        <div style="font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #111827;">🛡️ Sender Trust:</div>
        <div style="padding: 8px 10px; background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; font-weight: 600; color: #111827;">
          ${senderTrustLabel}
        </div>
      </div>
      ${linksSection}
    </div>
  `;
}

/**
 * Create and display reopen chip
 * Fixed to bottom-right for guaranteed visibility on all screen sizes
 */
function createReopenChip(result: MLAnalysisResult): void {
  clearPendingCloseAnimation();
  removeReopenChip();

  console.log('[Chip] Creating chip with result:', result.risk_score);

  const colors = getRiskColors(result.risk_score);
  const chip = document.createElement('button');
  chip.id = REOPEN_CHIP_ID;

  chip.style.cssText = `
    position: fixed !important;
    bottom: 24px !important;
    right: 24px !important;
    top: auto !important;
    left: auto !important;
    z-index: 2147483647 !important;
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    align-items: center;
    gap: 6px;
    pointer-events: auto !important;
    padding: 10px 18px;
    background: ${colors.bgColor};
    border: 2px solid ${colors.borderColor};
    border-radius: 24px;
    font-size: 13px;
    font-weight: 700;
    color: ${colors.color};
    cursor: pointer;
    white-space: nowrap;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 16px rgba(0,0,0,0.18);
    transition: all 0.2s ease;
  `;
  chip.innerHTML = `${colors.emoji} ${result.risk_score}/100 — View Risk`;
  chip.title = 'Click to view phishing risk details';

  // Hover effects
  chip.addEventListener('mouseover', () => {
    chip.style.transform = 'translateY(-2px)';
    chip.style.boxShadow = '0 6px 20px rgba(0,0,0,0.22)';
  });
  chip.addEventListener('mouseout', () => {
    chip.style.transform = 'translateY(0)';
    chip.style.boxShadow = '0 4px 16px rgba(0,0,0,0.18)';
  });

  // Click to reopen banner
  chip.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    console.log('[Chip] Clicked - reopening banner');
    
    // Disconnect observer BEFORE removing chip to avoid loop
    if (chipObserver) {
      chipObserver.disconnect();
      chipObserver = null;
    }
    
    removeReopenChip();
    displayWarningBanner(result);
    console.log('[Banner] Reopened from chip');
  });

  try {
    if (document.body) {
      document.body.appendChild(chip);

      // Force visibility after append — fights Gmail repaints
      void chip.offsetHeight; // force reflow so animation triggers
      chip.classList.add('phish-chip-enter');
      chip.style.setProperty('display', 'flex', 'important');
      chip.style.setProperty('visibility', 'visible', 'important');
      chip.style.setProperty('opacity', '1', 'important');
      chip.style.setProperty('bottom', '24px', 'important');
      chip.style.setProperty('right', '24px', 'important');
      chip.style.setProperty('top', 'auto', 'important');
      chip.style.setProperty('z-index', '2147483647', 'important');

      // MutationObserver: if anything sets display:none, immediately fight back
      if (chipObserver) chipObserver.disconnect();
      chipObserver = new MutationObserver(() => {
        const el = document.getElementById(REOPEN_CHIP_ID);
        if (el && el.style.display === 'none') {
          console.log('[Chip] display:none detected — forcing visible');
          el.style.setProperty('display', 'flex', 'important');
          el.style.setProperty('visibility', 'visible', 'important');
          el.style.setProperty('opacity', '1', 'important');
        }
      });
      chipObserver.observe(chip, {
        attributes: true,
        attributeFilter: ['style']
      });

      console.log('[Chip] Reopen chip created (bottom-right, observer active)');
    }
  } catch (error) {
    console.log('[Chip] Failed to append chip:', error);
  }
}

/**
 * Remove reopen chip
 */
function removeReopenChip(): void {
  if (chipObserver) {
    chipObserver.disconnect();
    chipObserver = null;
  }
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
    closeBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const banner = document.getElementById(BANNER_ID);
      if (banner) {
        clearPendingCloseAnimation();
        banner.style.animation = "slideUp 0.3s ease-in-out";
        closeAnimationTimeoutId = window.setTimeout(() => {
          banner.remove();
          // Create reopen chip after banner is closed
          if (lastAnalysisResult) {
            createReopenChip(lastAnalysisResult);
            console.log("[Banner] Closed - Reopen chip created");
          }
          closeAnimationTimeoutId = null;
        }, 300);
      }
    });

    closeBtn.addEventListener("mouseover", () => {
      closeBtn.style.opacity = "0.8";
      closeBtn.style.transform = "scale(1.2)";
    });
    closeBtn.addEventListener("mouseout", () => {
      closeBtn.style.opacity = "1";
      closeBtn.style.transform = "scale(1)";
    });
  }

  // Toggle details
  if (toggleBtn && detailsPanel) {
    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const isHidden = detailsPanel.classList.contains("hidden");

      if (isHidden) {
        detailsPanel.classList.remove("hidden");
        toggleBtn.textContent = "Hide Details ▲";
        console.log("[Banner] Details expanded");
      } else {
        detailsPanel.classList.add("hidden");
        toggleBtn.textContent = "Show Details ▾";
        console.log("[Banner] Details collapsed");
      }
    });

    toggleBtn.addEventListener("mouseover", () => {
      toggleBtn.style.opacity = "0.9";
    });
    toggleBtn.addEventListener("mouseout", () => {
      toggleBtn.style.opacity = "1";
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
    console.log("[Banner] Removing old banner with ID:", BANNER_ID);
    banner.remove();
    console.log("[Banner] Old banner removed");
  } else {
    console.log("[Banner] No existing banner found to remove");
  }
  // Note: Do NOT remove chip here — it should persist independently
}

/**
 * Display risk badge next to subject
 */
export function displayRiskBadge(riskScore: number, riskLevel: string): void {
  removeRiskBadge();

  const subject = document.querySelector("h2.hP") as HTMLElement | null;
  if (!subject) {
    return;
  }

  const colors = getRiskColors(riskScore);
  const badge = document.createElement("span");
  badge.id = "ml-risk-badge";
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
  console.log("[Badge] Displayed");
}

/**
 * Remove risk badge
 */
export function removeRiskBadge(): void {
  const badge = document.getElementById("ml-risk-badge");
  if (badge) {
    badge.remove();
  }
}

/**
 * Show safe email notification (auto-disappears)
 */
export function showSafeBadge(): void {
  removeWarningBanner();
  displayRiskBadge(0, "SAFE");

  const notification = document.createElement("div");
  notification.id = "ml-safe-notification";
  notification.style.cssText = `
    position: fixed;
    top: 75px;
    right: 12px;
    z-index: 2147483647;
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
  notification.innerHTML = "✅ Email appears safe";

  try {
    if (document.body) {
      document.body.appendChild(notification);
      console.log("[Badge] Safe notification shown");
    }
  } catch (error) {
    console.log("[Badge] Failed to append notification:", error);
    return;
  }

  setTimeout(() => {
    try {
      if (notification && notification.parentElement) {
        notification.style.transition = "opacity 0.3s";
        notification.style.opacity = "0";
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
