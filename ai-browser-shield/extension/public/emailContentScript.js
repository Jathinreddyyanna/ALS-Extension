// Prevent double injection
if (window.__reader_content_script_installed) {
  console.log('Reader content script already installed');
} else {
  window.__reader_content_script_installed = true;
  console.log('VAGABonds Content Script Loaded');

  function isGmail() { return location.hostname.includes('mail.google.com'); }
  function isWhatsApp() { return location.hostname.includes('web.whatsapp.com'); }
  function isTelegram() { return location.hostname.includes('web.telegram.org'); }

  function trimAndCleanText(text) {
    if (!text) return '';
    return text.split('\n').map(l => l.trim()).filter(l => l.length > 0).join('\n').replace(/\n\n+/g, '\n\n');
  }

  const style = document.createElement('style');
  style.id = 'vagabonds-styles';
  style.textContent = `
    @keyframes rainbowMove {
      0% { background-position: 0% 50%; }
      100% { background-position: 200% 50%; }
    }

    .vagabonds-highlight {
      transition: all 0.5s ease !important;
      box-sizing: border-box !important;
      border-radius: 8px !important;
    }

    .vagabonds-processing {
      padding: 6px 10px !important;
      border: 4px solid transparent !important;
      background:
        linear-gradient(white, white) padding-box,
        linear-gradient(90deg, red, orange, yellow, green, blue, violet, red) border-box !important;
      background-size: 200% 200% !important;
      animation: rainbowMove 3s linear infinite !important;
      color: #333 !important;
    }

    .vagabonds-safe {
      background-color: #2ecc40 !important;
      color: #fff !important;
      border: 2px solid #2ecc40 !important;
      animation: none !important;
      padding: 6px 10px !important;
    }

    .vagabonds-suspicious {
      background-color: #ffcc00 !important;
      color: #000 !important;
      border: 2px solid #ffcc00 !important;
      animation: none !important;
      padding: 6px 10px !important;
    }

    .vagabonds-dangerous {
      background-color: #ff3b3b !important;
      color: #fff !important;
      border: 2px solid #ff3b3b !important;
      animation: none !important;
      padding: 6px 10px !important;
    }
  `;
  document.head.appendChild(style);

  let lastPredictionData = null;
  let lastSubjectText = "";

  function applyHighlight(element, label) {
    if (!element) return;
    element.classList.add('vagabonds-highlight');
    element.classList.remove('vagabonds-processing', 'vagabonds-safe', 'vagabonds-suspicious', 'vagabonds-dangerous');
    void element.offsetWidth;
    if (label === 'processing') {
      element.classList.add('vagabonds-processing');
    } else if (label === 'safe') {
      element.classList.add('vagabonds-safe');
    } else if (label === 'suspicious') {
      element.classList.add('vagabonds-suspicious');
    } else if (label === 'dangerous' || label === 'scam') {
      element.classList.add('vagabonds-dangerous');
    }
    element.setAttribute('data-risk-highlight', label);
  }

  function isValidWhatsAppTitle(el) {
    const text = (el.innerText || '').trim().toLowerCase();
    const invalidStrings = ['click here', 'contact info', 'group info', 'online', 'typing...', 'last seen'];
    if (invalidStrings.some(s => text.includes(s))) return false;
    if (text.length > 50) return false;
    return true;
  }

  function getSubjectElement() {
    if (isGmail()) {
      const selectors = ['h2.hP', 'h2[data-subject-threading]', 'h2[role="heading"]', '[data-subject]', '.hP', '.ha h2', 'div[role="main"] h2'];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) return el;
      }
    } else if (isWhatsApp()) {
      const header = document.querySelector('#main header');
      if (header) {
        const potentialTitles = header.querySelectorAll('span[dir="auto"], div[role="button"] span');
        for (const el of potentialTitles) {
          if (el.innerText && isValidWhatsAppTitle(el) && el.offsetParent !== null) return el;
        }
      }
    } else if (isTelegram()) {
      const selectors = ['.chat-info .title', '.chat-title', '.peer-title', '.top-bar .title', 'div[class*="chat-title"]', '.tg_head_peer_title'];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) return el;
      }
    }
    return null;
  }

  function highlightCurrentPlatform(label) {
    const el = getSubjectElement();
    if (el) applyHighlight(el, label);
  }

  function setupGlobalObserver() {
    const observer = new MutationObserver(() => {
      const el = getSubjectElement();
      if (el) {
        const currentText = el.innerText.trim();
        if (currentText !== lastSubjectText && currentText.length > 0) {
          console.log(`VAGABonds: Subject/Chat changed from "${lastSubjectText}" to "${currentText}". forcing PROCESSING.`);
          lastSubjectText = currentText;
          lastPredictionData = null;
          applyHighlight(el, 'processing');
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }
  setTimeout(setupGlobalObserver, 1000);

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'predictionResult' && request.data) {
      console.log("VAGABonds: Received Prediction", request.data);
      const data = request.data;
      lastPredictionData = data;
      const label = data.risk_label || data.final_risk_label || 'safe';
      console.log(`VAGABonds: Applying label "${label}" to UI`);
      chrome.storage.local.set({ currentAnalysis: data });
      highlightCurrentPlatform(label);
      sendResponse({ status: "received" });
    }
    return true;
  });

  function extractEmailData() {
    let emailData = { subject: '', from: '', body: '', links: [], platform: 'gmail' };
    try {
      const subjectEl = getSubjectElement();
      if (subjectEl) emailData.subject = (subjectEl.innerText || '').trim();

      const senderNameEl = document.querySelector('.gD');
      if (senderNameEl) emailData.from = senderNameEl.innerText.trim();

      const bodyElements = document.querySelectorAll('.a3s.aiL, .a3s.ajx, [role="main"] .mGp');
      for (const el of bodyElements) {
        if (el.offsetHeight > 0) {
          emailData.body = trimAndCleanText(el.innerText);
          break;
        }
      }

      if (!emailData.body) {
        const altBody = document.querySelector('.msg, .h7');
        if (altBody) emailData.body = trimAndCleanText(altBody.innerText);
      }

      if (emailData.body && emailData.body.length > 1500) emailData.body = emailData.body.substring(0, 1500);
      return emailData;
    } catch (e) {
      console.error(e);
      return emailData;
    }
  }

  function extractWhatsAppData() {
    const data = { subject: '', from: '', body: '', links: [], platform: 'whatsapp' };
    try {
      const titleEl = getSubjectElement();
      if (titleEl) data.subject = titleEl.getAttribute('title') || titleEl.innerText;

      const msgTextEls = document.querySelectorAll('.copyable-text span');
      let texts = [];
      const recent = Array.from(msgTextEls).slice(-20);
      recent.forEach(el => {
        const txt = el.innerText.trim();
        if (txt && txt.length > 2 && !texts.includes(txt)) texts.push(txt);
      });
      if (texts.length > 0) data.body = trimAndCleanText(texts.join('\n'));
      if (data.body && data.body.length > 1500) data.body = data.body.substring(0, 1500);
      return data;
    } catch (e) {
      return data;
    }
  }

  function extractTelegramData() {
    const data = { subject: '', from: '', body: '', links: [], platform: 'telegram' };
    try {
      const hdr = getSubjectElement();
      if (hdr) data.subject = hdr.innerText.trim();

      const msgs = document.querySelectorAll('.message .text-content, .message .message-text, .message-content-wrapper');
      let texts = [];
      const recent = Array.from(msgs).slice(-10);
      recent.forEach(el => { if (el.innerText) texts.push(el.innerText); });
      if (texts.length > 0) data.body = trimAndCleanText(texts.join('\n'));
      if (data.body && data.body.length > 1500) data.body = data.body.substring(0, 1500);
      return data;
    } catch (e) {
      return data;
    }
  }

  function watchForChanges() {
    let lastSent = null;
    let candidateStr = null;
    let candidateCount = 0;
    setInterval(() => {
      let data = {};
      if (isGmail()) data = extractEmailData();
      else if (isWhatsApp()) data = extractWhatsAppData();
      else if (isTelegram()) data = extractTelegramData();

      if (data && (data.body.length > 20 || data.subject.length > 6)) {
        data.host = location.hostname;
        const dataStr = JSON.stringify(data);

        if (data.subject !== lastSubjectText) {
          console.log("VAGABonds: Subject/Chat sync update to:", data.subject);
          lastSubjectText = data.subject;
          highlightCurrentPlatform('processing');
        }

        if (dataStr === candidateStr) candidateCount += 1;
        else {
          candidateStr = dataStr;
          candidateCount = 1;
        }

        if (dataStr !== lastSent && candidateCount >= 2) {
          lastSent = dataStr;
          console.log(`VAGABonds: Sending extraction for ${data.platform}...`);
          chrome.runtime.sendMessage({ action: 'updateEmail', data: data });
        }
      }
    }, 700);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchForChanges);
  else watchForChanges();
}
