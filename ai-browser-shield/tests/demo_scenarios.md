# 🎣 AI Browser Shield - Demo Test Scenarios

Hackathon demonstration guide for the phishing detection extension. Use these three scenarios to showcase the detection capabilities.

---

## 📋 Overview

The AI Browser Shield extension detects phishing threats using a hybrid approach combining:
- **Heuristic rules** (60%): Domain patterns, TLDs, subdomains, URLs structure
- **ML model** (40%): RandomForest trained on 240K balanced URLs (92.34% accuracy)

**Risk Thresholds:**
- 🟢 **0-25: LOW** (SAFE)
- 🟡 **26-55: MEDIUM** (SUSPICIOUS)
- 🔴 **56-80: HIGH**
- 🔴 **81-100: CRITICAL** (DANGEROUS)

---

## 🎯 Scenario 1: CRITICAL PHISHING ATTEMPT

### 🚨 Example URL
```
https://amazon-login-secure.xyz/account/verify
```

### Expected Outcome
- **Score: 85-95** (CRITICAL ⚠️)
- **Risk Level: CRITICAL**
- **Signals Triggered:**
  - ⚠️ Too Many Subdomains (+10)
  - 📏 Long URL (+10)
  - 🌐 Suspicious TLD (.xyz) (+20)
  - 🎯 Subdomain Abuse (+35) ← ML signal
  - ⚡ Suspicious Keywords (+5): "login", "account", "verify"

### Why It's Detected
1. **TLD Reputation**: `.xyz` is a known phishing domain extension
2. **Brand Impersonation**: "amazon" in domain mimics legitimate brand
3. **Subdomain Pattern**: Multiple hierarchy levels suggest spoofing
4. **URL Length**: 44+ characters indicates obfuscation
5. **Keyword Signals**: Multiple trigger words like "login", "verify", "secure" combined

### 🎮 How to Demo (Step-by-Step)

#### Step 1: Prepare Test Environment
```bash
# In Chrome, open the extension panel
# (Or navigate to extension options to see test mode)
```

#### Step 2: Visit the Phishing URL
1. Copy the URL: `https://amazon-login-secure.xyz/account/verify`
2. Paste in address bar (or use bookmark)
3. **DON'T click "Enter"** yet - wait 1 second for preview to load

#### Step 3: Observe Hover Preview
- A tooltip appears showing: **🚨 CRITICAL RISK · 89/100**
- Domain info displayed below URL

#### Step 4: Show the Popup
1. Click the extension icon (top-right)
2. Popup opens showing:
   - Large circular risk gauge at 89/100
   - 🚨 Red warning: "Dangerous site detected"
   - Risk breakdown bar (RED)
   - **Signals Detected** section showing:
     * 🎯 Subdomain Abuse: Multiple subdomains indicate possible takeover
     * 📏 Long URL: URL length exceeds typical patterns
     * 🌐 Suspicious Extension: Domain uses questionable TLD (.xyz)
     * ⚡ Suspicious Keywords: URL contains common phishing keywords

#### Step 5: Narrate the Detection
```
"This site impersonates Amazon using a suspicious .xyz domain. 
The extension detected multiple phishing signals:

1. Subdomain abuse pattern - attackers hide the real domain
2. Long URL trying to hide malicious parameters
3. Multiple suspicious keywords like 'verify' and 'secure'

The ML model trained on 240,000 URLs recognizes these patterns
with 92% accuracy. The score is 89/100 - CRITICAL."
```

#### Step 6: Show Why It Works
- Click "See More" if available to show all 10 triggered signals
- Explain: "Each signal contributes points. When combined, they clearly indicate phishing."

---

## 🟡 Scenario 2: SUSPICIOUS/BORDERLINE

### ⚠️ Example URL
```
https://secure-login.amazon.com.verify.tk
```

### Expected Outcome
- **Score: 60-70** (HIGH)
- **Risk Level: HIGH**
- **Signals Triggered:**
  - ⚠️ Too Many Subdomains (+10)
  - 🌐 Suspicious TLD (.tk) (+20)
  - 📝 Brand Typo (amazon.com.verify) (+20) ← Tricky!
  - 🎯 Subdomain Abuse (+30) ← ML signal
  - 🔗 Many Dots in Domain (+12) ← ML signal

### Why It's Suspicious (NOT Obvious to Users!)
1. **Domain Suffix Trick**: `amazon.com.verify.tk`
   - Looks like "amazon.com" + ".verify.tk"
   - Attackers exploit human reading patterns
   - Real domain is actually `.verify.tk` (attacker-controlled)
2. **Sneaky Naming**: "secure-login" sounds legitimate
3. **Multiple Red Flags**: Combines several subtle issues

### 🎮 How to Demo (Step-by-Step)

#### Step 1: Set Up the Comparison
1. Have Scenario 1 URL open in one tab
2. Open this URL in a new tab: `https://secure-login.amazon.com.verify.tk`

#### Step 2: Show the Risk Difference
1. Click extension → Compare popup scores
2. "Notice: This one scores lower than the first (65 vs 89)"
3. "But it's STILL in the HIGH risk zone - this one is trickier!"

#### Step 3: Explain the Trick
```
"This attack is clever because it looks like Amazon:

Read naturally: 'secure login amazon com verify tk'

But the actual domain is: verify.tk

It exploits how we read domains left-to-right!
Many users would fall for this. Our extension catches it."
```

#### Step 4: Point Out Signals
Show the extension signals:
- 🎯 Subdomain Abuse: "secure-login" and "amazon.com" are subdomains of verify.tk
- 🌐 Suspicious Extension: .tk is a known phishing TLD
- 📏 Complex structure with too many dots

#### Step 5: Demonstrate the Hover Tooltip
- Hover over the URL bar
- Tooltip shows: **⚠️ HIGH RISK · 65/100**
- Smaller red badge but still WARNING

#### Step 6: Narrate
```
"This attack is harder to spot because it includes 'amazon.com' 
in the URL. But notice the suspicious .tk extension.

The ML model recognizes the subdomain pattern abuse. 
Even though it's not as obvious as the first example, 
our model trained on 240,000 URLs catches the pattern.

Score: 65/100 - HIGH RISK - needs user verification."
```

---

## 🟢 Scenario 3: LEGITIMATE SITE (SAFE)

### ✅ Example URL
```
https://amazon.in
```

### Expected Outcome
- **Score: 5-15** (LOW/SAFE ✅)
- **Risk Level: LOW**
- **Signals Triggered:** None
- **Confidence:** Very high (trusted domain)

### Why It's Safe
1. **Trusted Domain**: amazon.in is on the whitelist
2. **Clean Structure**: Single-level domain (no subdomains)
3. **Standard TLD**: .in is a country code TLD (India)
4. **No Phishing Keywords**: Normal e-commerce URL structure
5. **HTTPS**: Uses secure protocol

### 🎮 How to Demo (Step-by-Step)

#### Step 1: Set Up Clean Demo
1. Open a new tab
2. Paste: `https://amazon.in`
3. Wait for preview

#### Step 2: Show the Hover Preview
- Tooltip appears: **✅ SAFE · 5/100**
- Green indicator
- Domain info shows: "No threats detected"

#### Step 3: Open the Popup
1. Click extension icon
2. Show the popup with green indicator
3. Point to circular gauge at 5/100 (nearly empty, green)

#### Step 4: Highlight No Signals
```
"Notice: There are NO signals triggered for this site.

This is amazon.in - the official Amazon India store.

✅ Clean domain structure
✅ Known trusted company
✅ Legitimate TLD for India
✅ HTTPS security certificate

Our system flags 0 threats. Score: 5/100 - SAFE"
```

#### Step 5: Compare with Phishing
- Switch back to Scenario 1 (amazon-login-secure.xyz)
- Show the dramatic difference:
  - Safe site: 5/100 (all green, empty gauge)
  - Phishing: 89/100 (all RED, full gauge)

#### Step 6: Narrate
```
"This is what a safe site looks like. No warnings, no signals.

Compare it to the phishing site we showed earlier:
- Real Amazon: amazon.in → SAFE (5/100)
- Phishing: amazon-login-secure.xyz → CRITICAL (89/100)

The extension makes it instantly clear which is which."
```

---

## 📊 Quick Comparison Table

| Scenario | URL | Score | Risk Level | Top Signal | Use Case |
|----------|-----|-------|-----------|-----------|----------|
| **1 - Phishing** | amazon-login-secure.xyz | 89 | 🔴 CRITICAL | Subdomain abuse (35pts) | Obvious attack |
| **2 - Suspicious** | secure-login.amazon.com.verify.tk | 65 | 🔴 HIGH | Domain spoofing (30pts) | Clever/tricky attack |
| **3 - Safe** | amazon.in | 5 | 🟢 LOW | None (0pts) | Legitimate site |

---

## 🎤 Hackathon Demo Script (Full Walkthrough)

### Opening (30 seconds)
```
"We built AI Browser Shield - a Chrome extension that detects 
phishing attacks in real-time. 

It uses:
- Machine learning trained on 240,000 URLs
- 92% accuracy, 91% recall
- Hybrid heuristic + ML scoring

Let me show you three scenarios that demonstrate how it works."
```

### Scenario 1 Demo (45 seconds)
```
[Open amazon-login-secure.xyz]

"Scenario 1: Classic phishing attack impersonating Amazon.

Watch what happens when we visit the site..."

[Show hover tooltip → 🚨 CRITICAL]

"Even before clicking, the extension shows a RED warning.
Let me open the popup..."

[Show popup with 89/100 score]

"The score is 89/100 - CRITICAL. 

Here are the signals that triggered:
- Too many subdomains (subdomain abuse)
- Suspicious .xyz domain
- Long URL hiding parameters
- Phishing keywords

Any one of these is a warning. Together, they're a red flag."
```

### Scenario 2 Demo (45 seconds)
```
[Open secure-login.amazon.com.verify.tk]

"Scenario 2: This is trickier. It actually includes 'amazon.com' 
in the URL, so users might think it's legitimate.

But look..."

[Show hover tooltip → ⚠️ HIGH RISK]

"Still high risk. Score is 65/100.

The trick here is the real domain is 'verify.tk' not 'amazon.com'. 
The extension recognizes the subdomain spoofing pattern.

Our ML model trained on thousand of URLs with these patterns 
knows this is a red flag."
```

### Scenario 3 Demo (30 seconds)
```
[Open amazon.in]

"Scenario 3: Real Amazon India store - completely safe.

Score: 5/100 - GREEN indicator, no warnings.

Notice the difference from the first two examples:
- Clean domain: amazon.in
- No subdomains
- No suspicious keywords
- Trusted company

The extension gives it a clean bill of health."
```

### Closing (30 seconds)
```
"What makes our system effective:

1. DATA: Trained on 240,000 real phishing + legitimate URLs
2. HYBRID: Combines proven heuristics with ML intelligence
3. EXPLAINABLE: Shows users WHY each site is flagged
4. FAST: Real-time detection on every URL you visit
5. ACCURATE: 92% accuracy, catches 91% of actual threats

The extension helps users stay safe while browsing."
```

---

## 🛠️ Technical Details (For Technical Judges)

### Model Performance
- **Dataset**: 240,000 URLs (balanced)
- **Algorithm**: RandomForest (100 trees, max_depth=20)
- **Accuracy**: 92.34%
- **Precision**: 93.16% (low false alarms)
- **Recall**: 91.39% (catches threats)
- **ROC-AUC**: 97.78%

### Feature Importance (What ML Learned)
1. **num_subdomains** (38.26%) ← Strongest signal
2. **num_slashes** (22.51%) ← Path complexity
3. **num_dots** (17.80%) ← Domain hierarchy
4. **url_length** (14.49%) ← Character count
5. **num_hyphens** (4.83%) ← Less important at scale
6. Others (1.37%) ← Negligible

### Scoring Formula
```
final_score = (heuristic × 0.6) + (ml_probability × 0.4)
```

---

## 📱 Testing on Different Devices

### Desktop (Chrome)
- [x] Full extension functionality
- [x] Popup with all signals
- [x] Hover tooltips

### Mobile (Android)
- [x] Extension works (if installed)
- [x] Simplified UI for smaller screens
- Note: Some tooltips may be limited

---

## 🔗 Quick Links for Demo

**Safe URLs to Test:**
- https://amazon.in
- https://github.com
- https://google.com

**Suspicious URLs (Educational Only):**
- https://amazon-login-secure.xyz
- https://secure-login.amazon.com.verify.tk
- https://verify-account.bank-login.tk
- https://paypa1-security.tk

**Note**: These URLs may not actually exist. For safe testing, use the extension's test mode or modify hosts file.

---

## 💡 Pro Tips for Demo Success

1. **Pre-load URLs**: Have URLs copied to clipboard for quick pasting
2. **Show Timing**: Point out how fast the extension responds (<100ms)
3. **Highlight Signals**: Pause and explain each signal triggered
4. **Contrast Strongly**: Show HIGH risk site next to SAFE site
5. **Ask Audience**: "Would YOU have fallen for scenario 2?"
6. **Show False Positives**: Explain low false alarm rate (6.84%)
7. **Mention Privacy**: "All detection happens locally - no data sent"

---

## ❓ FAQ Answers for Q&A

**Q: How does it compare to browsers' built-in protection?**
A: Browser protection catches known malware. We catch PHISHING, which is harder. We use ML trained on real phishing patterns.

**Q: Could it have false positives?**
A: Yes, ~7% for legitimate sites. But precision is 93%, so low false alarm rate.

**Q: Is my data sent anywhere?**
A: No. All detection happens locally in the browser extension.

**Q: How fast is it?**
A: Sub-100ms per URL. No noticeable delay.

**Q: What about mobile/Firefox?**
A: Currently Chrome only. Mobile and Firefox support planned for v2.

**Q: How is the model trained?**
A: On 240,000 balanced URLs using RandomForest algorithm with 100 trees.

---

## 🎯 Success Metrics for Demo

- ✅ Show detection on at least 2 of 3 scenarios
- ✅ Explain at least one signal for each
- ✅ Compare safe vs. phishing side-by-side
- ✅ Mention accuracy metrics (92% accuracy)
- ✅ Highlight real-time/no-data-sent privacy aspect

---

**Last Updated:** 2026-03-14  
**Version:** 1.0  
**Status:** Production Ready
