let currentEmailData = {
  subject: '',
  from: '',
  fromEmail: '',
  to: '',
  body: '',
  timestamp: null,
  links: []
};

chrome.runtime.onInstalled.addListener(r => {
  if (r.reason == 'install') {
    chrome.tabs.create({
      url: 'onboarding-page.html'
    });
  }
});

// Track which hostname we've injected into per tabId to avoid repeated injections
const injectedTabs = new Map(); // tabId -> hostname

function getSupportedHost(url) {
  try {
    const h = new URL(url).hostname;
    if (h.includes('mail.google.com')) return 'mail.google.com';
    if (h.includes('web.whatsapp.com')) return 'web.whatsapp.com';
    if (h.includes('web.telegram.org')) return 'web.telegram.org';
  } catch (e) { }
  return null;
}

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (!tab || !tab.url) return;
  if (changeInfo.status !== 'complete') return; // wait until load complete

  const host = getSupportedHost(tab.url);
  if (!host) {
    if (injectedTabs.has(tabId)) injectedTabs.delete(tabId);
    return;
  }

  const prev = injectedTabs.get(tabId);
  if (prev === host) return; // already injected for this host

  chrome.scripting.executeScript({ files: ['contentScript.js'], target: { tabId: tabId } }, () => {
    if (chrome.runtime.lastError) {
      console.warn('Injection failed for tab', tabId, chrome.runtime.lastError);
      return;
    }
    injectedTabs.set(tabId, host);
    console.log('Injected reader content script into', host, 'tab', tabId);
  });
});

// Inject when a tab becomes active (handles existing open tabs)
chrome.tabs.onActivated.addListener(function (activeInfo) {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (!tab || !tab.url) return;
    const host = getSupportedHost(tab.url);
    if (!host) return;
    const prev = injectedTabs.get(activeInfo.tabId);
    if (prev === host) return;
    chrome.scripting.executeScript({ files: ['contentScript.js'], target: { tabId: activeInfo.tabId } }, () => {
      if (chrome.runtime.lastError) {
        console.warn('Activation injection failed for tab', activeInfo.tabId, chrome.runtime.lastError);
        return;
      }
      injectedTabs.set(activeInfo.tabId, host);
      console.log('Injected on activation into', host, 'tab', activeInfo.tabId);
    });
  });
});

// Clean up when tabs are removed
chrome.tabs.onRemoved.addListener((tabId) => {
  if (injectedTabs.has(tabId)) injectedTabs.delete(tabId);
});

// Debounce/cache mechanism: avoid duplicate ML calls per tab/message
// Using a global variable for cache to persist across messages
let predictionCache = {};
let lastRiskByTab = {};
const ML_BACKEND_URL = 'http://127.0.0.1:5000/predict';
const TRY_LOCAL_BACKEND = true;
let backendWarnedOnce = false;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  function clamp(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }

  function riskLabel(score) {
    if (score >= 0.7) return 'dangerous';
    if (score >= 0.4) return 'suspicious';
    return 'safe';
  }

  function riskRank(label) {
    if (label === 'dangerous' || label === 'scam') return 3;
    if (label === 'suspicious') return 2;
    if (label === 'safe') return 1;
    return 0;
  }

  function normalizeSubject(subject) {
    return (subject || '').toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function stabilizePrediction(tabId, data, prediction) {
    const now = Date.now();
    const incomingLabel = prediction.final_risk_label || prediction.risk_label || 'safe';
    const incomingRank = riskRank(incomingLabel);
    const key = `${tabId}:${normalizeSubject(data.subject)}`;
    const prev = lastRiskByTab[key];

    if (prev) {
      const prevRank = riskRank(prev.label);
      const ageMs = now - prev.ts;
      const bodyLen = (data.body || '').trim().length;

      // Prevent rapid downgrade from suspicious/dangerous to safe on partial DOM snapshots.
      if (prevRank > incomingRank && ageMs < 45000 && bodyLen < 180) {
        return {
          ...prev.result,
          explanation: `${prev.result.explanation || ''} Kept higher-risk result while message content stabilizes.`.trim()
        };
      }
    }

    lastRiskByTab[key] = {
      label: incomingLabel,
      result: prediction,
      ts: now
    };

    return prediction;
  }

  function runLocalFallbackAnalysis(data, reason) {
    const subject = (data.subject || '').toLowerCase();
    const body = (data.body || '').toLowerCase();
    const sender = (data.fromEmail || data.from || '').toLowerCase();
    const platform = data.platform || 'unknown';
    const text = `${subject}\n${body}`;
    const links = Array.isArray(data.links) ? data.links : [];

    let score = 0.05;
    const detected = [];

    const shortenerRe = /(bit\.ly|tinyurl|forms\.gle|t\.me|wa\.me|rb\.gy|goo\.gl)/i;
    const urgencyRe = /\b(urgent|immediately|act now|final warning|suspended|expire|last chance|verify now)\b/i;
    const rewardRe = /\b(prize|reward|bonus|gift|cash|lottery|free money|refund)\b/i;
    const credentialRe = /\b(password|otp|pin|cvv|bank account|ssn|aadhaar|verify your account)\b/i;
    const paymentRe = /\b(fee|payment|upi|wire transfer|crypto|bitcoin|transfer now)\b/i;
    const impersonationRe = /\b(bank|rbi|income tax|government|microsoft|google|amazon|hr team|admin)\b/i;
    const benignBulletinRe = /\b(holiday|circular|office closed|school closed|public holiday|notice|timetable|schedule|meeting agenda|minutes of meeting|event update|festival leave|vacation|academic calendar)\b/i;
    const phishingIntentRe = /\b(verify your account|login now|update password|share otp|share pin|cvv|bank details|transfer now|pay now|claim prize now|click here now|account suspended)\b/i;
    const ipUrlRe = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i;
    const hasShortenedLink = shortenerRe.test(text) || links.some(l => shortenerRe.test(l || ''));
    const hasIpLink = ipUrlRe.test(text) || links.some(l => ipUrlRe.test(l || ''));
    const hasHighRiskIntent = phishingIntentRe.test(text) || hasShortenedLink || hasIpLink || credentialRe.test(text);
    const isBenignBulletin = benignBulletinRe.test(text);

    if (hasShortenedLink) {
      score += 0.25;
      detected.push('Shortened or redirect-style link');
    }

    if (hasIpLink) {
      score += 0.25;
      detected.push('IP-based URL');
    }

    if (urgencyRe.test(text)) {
      score += 0.2;
      detected.push('Urgency pressure language');
    }

    if (rewardRe.test(text)) {
      score += 0.15;
      detected.push('Reward/lottery bait');
    }

    if (credentialRe.test(text)) {
      score += 0.2;
      detected.push('Sensitive credential request');
    }

    if (paymentRe.test(text)) {
      score += 0.2;
      detected.push('Payment request signal');
    }

    if (impersonationRe.test(text) && hasHighRiskIntent) {
      score += 0.1;
      detected.push('Authority/brand impersonation cues');
    }

    if (sender) {
      const freeMailRe = /@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|protonmail\.com)$/i;
      const suspiciousTldRe = /\.(xyz|top|online|site|click|info)$/i;

      if (freeMailRe.test(sender) && impersonationRe.test(text)) {
        score += 0.15;
        detected.push('Sender/domain mismatch');
      }
      if (suspiciousTldRe.test(sender)) {
        score += 0.2;
        detected.push('Suspicious sender domain');
      }
    }

    if (isBenignBulletin && !hasHighRiskIntent) {
      score = Math.min(score * 0.45, 0.35);
      detected.push('Informational bulletin language');
    }

    const finalScore = clamp(score, 0, 1);
    let label = riskLabel(finalScore);
    if (label === 'dangerous' && !hasHighRiskIntent) {
      label = 'suspicious';
    }

    return {
      risk_label: label,
      final_risk_label: label,
      final_score: finalScore,
      platform,
      detected_patterns: detected,
      explanation: `Local analysis used (${reason}). Risk score ${Math.round(finalScore * 100)}%. ${detected.length ? `Signals: ${detected.join(', ')}.` : 'No strong scam signals detected.'}`,
      engine: 'local-fallback'
    };
  }

  // Unique hash for each message (subject+body+platform)
  function getMessageHash(data) {
    // Include more body context + length to reduce collisions.
    const subject = (data.subject || '').slice(0, 120);
    const body = data.body || '';
    const bodyHead = body.slice(0, 320);
    const bodyLen = body.length;
    return btoa(encodeURIComponent(`${subject}|${bodyHead}|${bodyLen}|${data.platform || ''}`));
  }

  // ML prediction fetch logic
  async function fetchPrediction(data) {
    if (!TRY_LOCAL_BACKEND) {
      return runLocalFallbackAnalysis(data, 'backend disabled');
    }

    const url = ML_BACKEND_URL;
    const payload = {
      subject: data.subject || '',
      from: data.from || '',
      fromEmail: data.fromEmail || '',
      body: data.body || '',
      links: data.links || [],
      platform: data.platform || ''
    };

    console.log('[ML] API request sent:', payload);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 12000); // quick fallback for better UX

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) {
        return runLocalFallbackAnalysis(data, `backend error ${response.status}`);
      }

      const apiResult = await response.json();
      const label = apiResult.final_risk_label || apiResult.risk_label;
      if (!label) {
        return runLocalFallbackAnalysis(data, 'invalid backend response');
      }

      const result = {
        ...apiResult,
        risk_label: apiResult.risk_label || label,
        final_risk_label: apiResult.final_risk_label || label,
        final_score: typeof apiResult.final_score === 'number' ? apiResult.final_score : 0,
        detected_patterns: Array.isArray(apiResult.detected_patterns) ? apiResult.detected_patterns : []
      };
      console.log('[ML] API response received:', result);
      return result;
    } catch (err) {
      if (!backendWarnedOnce) {
        console.warn('[ML] Backend unreachable. Using local fallback analysis.', err && err.message ? err.message : err);
        backendWarnedOnce = true;
      }
      return runLocalFallbackAnalysis(data, err.message || 'backend unavailable');
    }
  }

  // Handle updateEmail action
  if (request.action === 'updateEmail') {
    const data = request.data || {};
    currentEmailData = {
      subject: data.subject || 'No Subject',
      from: data.from || 'Unknown Sender',
      fromEmail: data.fromEmail || '',
      to: data.to || 'Unknown',
      body: data.body || 'No content',
      links: data.links || [],
      platform: data.platform || 'unknown',
      timestamp: new Date().toLocaleString()
    };

    // Save to local storage for popup
    chrome.storage.local.set({ lastEmail: currentEmailData }, () => {
      // acknowledged storage set
    });

    // Acknowledge receipt immediately to keep content script happy
    // (We'll send the prediction result asynchronously via tabs.sendMessage)
    sendResponse({ success: true, status: 'processing' });

    // --- ML PREDICTION FLOW ---

    const tabId = sender.tab ? sender.tab.id : null;
    if (!tabId) {
      console.warn('No tabId for ML prediction');
      return true; // keep channel open (though we already responded)
    }

    const msgHash = getMessageHash(currentEmailData);

    // Check Cache
    if (predictionCache[tabId] && predictionCache[tabId].hash === msgHash) {
      console.log('[ML] Duplicate message content, skipping API call. Re-sending cached result.');
      // Re-send cached result in case UI needs refresh
      chrome.tabs.sendMessage(tabId, {
        type: 'predictionResult',
        data: predictionCache[tabId].result
      }).catch(() => { }); // ignore if tab closed
      return true;
    }

    // New content -> Call API
    (async () => {
      // 🌈 SET PROCESSING STATE - Triggers rainbow border
      chrome.storage.local.set({ processingState: true }, () => {
        console.log('[ML] Processing state set - rainbow border should appear');
      });

      // Notify content script of processing state
      chrome.tabs.sendMessage(tabId, {
        type: 'predictionResult',
        data: { final_risk_label: 'processing', risk_label: 'processing', confidence: 0 }
      }).catch(() => { });

      const rawPrediction = await fetchPrediction(currentEmailData);
      const prediction = stabilizePrediction(tabId, currentEmailData, rawPrediction);

      // 🌈 CLEAR PROCESSING STATE - Removes rainbow border
      chrome.storage.local.set({ processingState: false }, () => {
        console.log('[ML] Processing state cleared');
      });

      // Update Cache
      if (prediction && prediction.final_risk_label && prediction.final_risk_label !== 'error') {
        predictionCache[tabId] = {
          hash: msgHash,
          timestamp: Date.now(),
          result: prediction
        };
      }

      // Send result to content script
      console.log('[ML] Sending prediction to content script:', prediction);
      chrome.tabs.sendMessage(tabId, {
        type: 'predictionResult',
        data: prediction
      }, () => {
        if (chrome.runtime.lastError) {
          // Tab might have been closed or refreshed
          console.warn('Prediction sendMessage failed (tab likely closed):', chrome.runtime.lastError.message);
        } else {
          console.log('[ML] ✅ Prediction successfully sent to content script');
        }
      });
    })();

    // return true to indicate async response (even though we already called sendResponse, good practice)
    return true;
  }

  // Handle getEmail action (for popup)
  if (request.action === 'getEmail') {
    sendResponse({ email: currentEmailData });
  }
});

