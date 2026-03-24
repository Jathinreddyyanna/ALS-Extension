# 🧪 Interactive Testing Guide

**Step-by-step instructions for testing each system**

---

## 📝 Before You Start

1. **Open Chrome**
2. **Open 3 tabs:**
   - Tab 1: Gmail (test 1)
   - Tab 2: Test URLs (test 2)
   - Tab 3: DevTools (F12 - for debugging)

3. **Check extension is enabled:**
   - chrome://extensions/
   - Toggle "AI Browser Shield" to ON
   - See icon in top-right corner

4. **Disable other extensions** (optional but recommended)

---

## 🎯 Test 1: Gmail Phishing Email Detection

### Setup (2 minutes)
1. Go to https://gmail.com (or your Gmail instance)
2. Login with test account
3. Open DevTools: F12 → Console tab
4. Check for errors (should be none)

### Test 1.1: Critical Phishing Email ⚠️

**Create test email:**
```
TO: recipient@gmail.com
FROM: support@amazon-verify.tk
SUBJECT: Account Suspended - Verify Immediately!
BODY:
Your account has been blocked due to suspicious activity.

Click here to restore access:
https://verify-account.tk/amazon/login

DO NOT IGNORE THIS EMAIL!
-Amazon Support
```

**Steps:**
1. [ ] Compose new email with above content
2. [ ] Send to yourself
3. [ ] Go to Inbox
4. [ ] **Observe email subject line** - should be highlighted RED
5. [ ] **Hover over subject** - should see popup "DANGEROUS"
6. [ ] **Click on email** - read message
7. [ ] **Click extension icon** (top-right)
8. [ ] **Observe popup**

**Expected Results:**
```
✅ Subject line is RED
✅ Risk indicator shows CRITICAL (81-100)
✅ Large red gauge circle
✅ Warning message: "This appears to be a phishing attempt"
✅ Signals shown:
   - Urgency language detected
   - Suspicious sender domain (amazon-verify.tk)
   - Brand impersonation (Amazon)
   - Malicious link pattern
✅ Confidence: 80%+
```

**Document Result:**
```
Test 1.1 Status: [PASS / FAIL]
Risk Score: ____ / 100
Color: [RED / ORANGE / YELLOW / GREEN]
Signals Detected: ___________
```

---

### Test 1.2: Credential Harvesting Email

**Create test email:**
```
FROM: security@bank-login.ml
SUBJECT: Update Your Banking Details
BODY:
Please confirm your account information for security verification:

Full Name: _________________
Account Number: _________________
Password: _________________
PIN: _________________

Failure to update will result in account suspension.
```

**Steps:**
1. [ ] Create and send this email
2. [ ] Go to Inbox, find the email
3. [ ] Check subject highlighting
4. [ ] Click extension icon

**Expected Results:**
```
✅ Subject highlighted YELLOW or RED
✅ Risk score: 60-85 (HIGH/CRITICAL)
✅ Attack type: "Credential Harvesting"
✅ Signals:
   - Request for sensitive information
   - Credential-related keywords
   - Suspicious TLD (.ml)
   - Authority impersonation
```

**Document Result:**
```
Test 1.2 Status: [PASS / FAIL]
Risk Score: ____ / 100
Attack Type: ___________
```

---

### Test 1.3: Lottery/Prize Scam Email

**Create test email:**
```
FROM: noreply@lottery-scam.tk
SUBJECT: Congratulations! You've Won $1,000,000!
BODY:
You have been selected as the Grand Prize Winner!

Your Prize: $1,000,000 USD
Claim Code: WINNER2024

Click here to claim your prize:
https://claim-prize.tk/verify?user=target

This offer expires in 24 hours!
```

**Steps:**
1. [ ] Create and send
2. [ ] Find in Inbox
3. [ ] Observe highlighting
4. [ ] Check popup

**Expected Results:**
```
✅ Subject RED or YELLOW
✅ Risk score: 65-85 (HIGH)
✅ Signals:
   - Prize/reward keywords
   - Urgency (24 hours)
   - Suspicious sender
   - Phishing link
```

**Document Result:**
```
Test 1.3 Status: [PASS / FAIL]
Risk Score: ____ / 100
```

---

### Test 1.4: Finance/Bank Fraud Email

**Create test email:**
```
FROM: noreply@bank-alert.xyz
SUBJECT: Transaction Alert - Verify Your Account Immediately
BODY:
We detected unusual activity on your account.

Unusual Transaction:
Date: 03-14-2026
Amount: $5,000
Location: Unknown

To prevent account freeze, verify your credentials:
Click here to verify

Time-sensitive: Respond within 2 hours
```

**Steps:**
1. [ ] Create and send
2. [ ] Check highlighting
3. [ ] View popup

**Expected Results:**
```
✅ Subject RED or YELLOW
✅ Risk score: 55-75 (MEDIUM/HIGH)
✅ Signals:
   - Authority keywords (bank, transaction, account)
   - Urgency (2 hours, prevent freeze)
   - Suspicious TLD
   - Verification request
```

**Document Result:**
```
Test 1.4 Status: [PASS / FAIL]
Risk Score: ____ / 100
```

---

### Test 1.5: Legitimate Email (Negative Test)

**Create test email:**
```
FROM: noreply@teams.microsoft.com
SUBJECT: You have a new message in Microsoft Teams
BODY:
You have a new message in Microsoft Teams.

Sign in to read it: https://teams.microsoft.com

Microsoft Teams
```

**Steps:**
1. [ ] Create and send
2. [ ] Go to Inbox
3. [ ] Check subject - should NOT be highlighted
4. [ ] Click extension icon

**Expected Results:**
```
✅ Subject NOT highlighted
✅ NO red banner
✅ Risk score: 5-15 (LOW/SAFE)
✅ NO warning
✅ NO signals shown
✅ Green indicator
```

**Document Result:**
```
Test 1.5 Status: [PASS / FAIL]
Risk Score: ____ / 100
Color: [GREEN]
Warnings Shown: [NONE]
```

---

### Email Detection Summary

```
Completed: [ __ / 5 tests ]

Overall Status: [✅ PASS / ⚠️ PARTIAL / ❌ FAIL]

Issues Found:
_________________________________
_________________________________

Notes:
_________________________________
```

---

## 🌐 Test 2: URL Phishing Page Detection

### Setup (1 minute)
1. [ ] Open new Chrome tab
2. [ ] Click extension icon to open popup
3. [ ] Open DevTools (F12) → Network tab

### Test 2.1: Critical Phishing URL

**URL:** `https://amazon-login-secure.xyz/account/verify`

**Steps:**
1. [ ] Click address bar (Ctrl+L)
2. [ ] Type the URL (DON'T press Enter yet)
3. [ ] Wait 300ms, look at extension icon
4. [ ] Observe hover preview tooltip appear below address bar
5. [ ] Note the color and score in preview
6. [ ] Press Enter to visit the page (optional - may trigger overlay)
7. [ ] Click extension icon to see full popup

**Expected Results:**
```
Hover Preview:
✅ Shows "🚨 CRITICAL RISK" 
✅ Score: 85-95 / 100
✅ Color: DARK RED / RED

Extension Popup:
✅ Large gauge showing 85-95
✅ Red danger circle
✅ Warning message: "Dangerous phishing attempt detected"
✅ Signals section shows:
   [ ] Subdomain Abuse (explanation visible)
   [ ] Suspicious TLD (.xyz)
   [ ] Long URL pattern
   [ ] Suspicious keywords (amazon, login, secure, verify)
✅ Breakdown: Heuristic XX%, Model YY%
```

**Performance Check:**
```
Time to preview: _____ ms (target < 300ms)
Preview appeared: [YES / NO]
Override available: [YES / NO]
```

**Document Result:**
```
Test 2.1 Status: [PASS / FAIL / PARTIAL]
Risk Score: ____ / 100
Preview Speed: ____ ms
Signals Detected: ___________
```

---

### Test 2.2: Suspicious URL - Domain Spoofing

**URL:** `https://secure-login.amazon.com.verify.tk`

**Steps:**
1. [ ] Click address bar
2. [ ] Type URL
3. [ ] Wait for preview
4. [ ] Observe score and color
5. [ ] Compare to Test 2.1 (should be lower)

**Expected Results:**
```
Hover Preview:
✅ Shows "⚠️ HIGH RISK" (different from CRITICAL)
✅ Score: 60-70 / 100
✅ Color: ORANGE / YELLOW-RED

Difference from Test 2.1:
✅ Lower score (60-70 vs 85-95)
✅ Different color (orange vs red)
✅ Different signals

Signals:
✅ Domain Spoofing Detected (key signal)
✅ Subdomain confusion
✅ Suspicious TLD
```

**Document Result:**
```
Test 2.2 Status: [PASS / FAIL]
Risk Score: ____ / 100
Color: [RED / ORANGE / YELLOW]
Comparison to 2.1: [LOWER / SAME / HIGHER] ✅ Should be LOWER
```

---

### Test 2.3: Typosquatting URL

**URL:** `https://amaz0n-login.xyz/account`

**Steps:**
1. [ ] Type URL in address bar
2. [ ] Wait for preview

**Expected Results:**
```
✅ Preview shows MEDIUM/HIGH risk
✅ Score: 50-70 / 100
✅ Color: ORANGE / YELLOW

Signals:
✅ Brand typo detected (amaz0n vs amazon)
✅ Suspicious TLD (.xyz)
✅ Generic keywords
```

**Document Result:**
```
Test 2.3 Status: [PASS / FAIL]
Risk Score: ____ / 100
```

---

### Test 2.4: Legitimate Domain - Single Word

**URL:** `https://amazon.in`

**Steps:**
1. [ ] Type in address bar
2. [ ] Wait for preview

**Expected Results:**
```
✅ Preview shows "✅ SAFE"
✅ Score: 5 / 100
✅ Color: GREEN

Indicators:
✅ NO warning
✅ NO red badge on icon
✅ NO signals
✅ Clean green circle in popup

Difference from 2.1:
✅ Dramatically different from phishing URLs
✅ Clear visual distinction
```

**Document Result:**
```
Test 2.4 Status: [PASS / FAIL]
Risk Score: ____ / 100
Color: [GREEN / YELLOW / RED]
Warnings: [NONE / SOME]
```

---

### Test 2.5: Trusted Domain - Global Tech

**URL:** `https://github.com`

**Steps:**
1. [ ] Type URL
2. [ ] Wait for preview
3. [ ] Visit site and check for warning overlay

**Expected Results:**
```
✅ Score: 5 / 100 (SAFE)
✅ Color: GREEN
✅ NO warning overlay on actual page
✅ NO warning banner
✅ Smooth browsing experience
```

**Document Result:**
```
Test 2.5 Status: [PASS / FAIL]
Overlay Shown: [YES / NO] ✅ Should be NO
```

---

### Test 2.6: Link Hover Preview

**Steps:**
1. [ ] Navigate to any website with links (e.g., reddit.com, hackernews.com)
2. [ ] Hover cursor over a link (don't click)
3. [ ] Wait 300ms for tooltip
4. [ ] Observe preview appears near cursor
5. [ ] Move to another link and repeat

**Expected Behavior:**
```
For suspicious links:
✅ Tooltip appears with warning
✅ Shows score and color
✅ Disappears when mouse leaves link

For legitimate links:
✅ Tooltip appears (or may be skipped)
✅ Shows "✅ SAFE"
✅ Green color
```

**Document Result:**
```
Test 2.6 Status: [PASS / FAIL]
Tooltip Response Time: ____ ms
Tested On: ___________
```

---

### URL Detection Summary

```
Test 2.1 (Critical Phishing): [✅ PASS / ❌ FAIL]
Test 2.2 (Domain Spoofing): [✅ PASS / ❌ FAIL]
Test 2.3 (Typosquatting): [✅ PASS / ❌ FAIL]
Test 2.4 (Legitimate): [✅ PASS / ❌ FAIL]
Test 2.5 (Trusted): [✅ PASS / ❌ FAIL]
Test 2.6 (Hover Preview): [✅ PASS / ❌ FAIL]

Overall Status: [✅ PASS / ⚠️ PARTIAL / ❌ FAIL]
Completed: [ __ / 6 tests ]

Issues:
_________________________________

Notes:
_________________________________
```

---

## 📥 Test 3: Suspicious File Download Detection

### Setup (1 minute)
1. [ ] Chrome Downloads page: chrome://downloads/
2. [ ] Have this tab open
3. [ ] Another tab for file hosting

### Test 3.1: Executable File (.exe)

**Steps:**
1. [ ] Create or find a harmless .exe file locally
   - Option A: Rename any file to `.exe` (won't actually execute)
   - Option B: Download a safe installer (Python, Node, etc.)
2. [ ] Right-click the file
3. [ ] "Save link as..." or drag to downloads
4. [ ] Observe warning (if any) **APPEARS BEFORE** download completes
5. [ ] Check chrome://downloads for warning message

**Expected Results:**
```
✅ Warning appears (either popup or inline message)
✅ Risk level: "HIGH" or "CRITICAL"
✅ Color: RED
✅ Recommendation: "Block" / "Quarantine" / "Delete"
✅ Reason given: "Executable file (.exe) can run code"

If blocked:
✅ Download doesn't complete
✅ Clear explanation why

If warning only:
✅ Download completes
✅ Clear file risk indicator
```

**Document Result:**
```
Test 3.1 Status: [PASS / FAIL / PARTIAL]
Warning Shown: [YES / NO]
Risk Level: __________
Recommendation: __________
```

---

### Test 3.2: Batch File (.bat)

**Steps:**
1. [ ] Create or find a .bat file
2. [ ] Attempt download
3. [ ] Check for warning

**Expected Results:**
```
✅ Warning shown
✅ Risk: "HIGH"
✅ Color: RED
✅ Message: "Batch file (.bat) can execute commands"
```

**Document Result:**
```
Test 3.2 Status: [PASS / FAIL]
Risk Level: __________
```

---

### Test 3.3: ZIP Archive

**Steps:**
1. [ ] Download or create a .zip file
2. [ ] Attempt download
3. [ ] Observe warning

**Expected Results:**
```
✅ Warning shown
✅ Risk: "MEDIUM"
✅ Color: YELLOW / ORANGE
✅ Message: "Archive may contain harmful files"
✅ Recommendation: "Scan before opening"
```

**Document Result:**
```
Test 3.3 Status: [PASS / FAIL]
Risk Level: __________
```

---

### Test 3.4: Archive from IP Address

**Steps:**
1. [ ] Create .rar or .zip file on IP address (192.168.x.x or similar)
2. [ ] Attempt download
3. [ ] Note the warning (should mention IP address)

**Expected Results:**
```
✅ Risk: "MEDIUM"
✅ Special message: "File from IP address (not domain)"
✅ More caution than normal file
```

**Document Result:**
```
Test 3.4 Status: [PASS / FAIL]
Risk Level: __________
Special IP Warning: [YES / NO]
```

---

### Test 3.5: PDF Document

**Steps:**
1. [ ] Download a legitimate PDF (e.g., from GitHub)
2. [ ] Observe warning (or lack thereof)

**Expected Results:**
```
✅ NO warning (or minimal warning like "check source")
✅ Risk: "LOW" / "SAFE"
✅ Color: GREEN
✅ Recommendation: "Allow"
✅ Download completes normally
```

**Document Result:**
```
Test 3.5 Status: [PASS / FAIL]
Risk Level: __________
Warning Shown: [NONE / MINIMAL]
```

---

### Test 3.6: Image File

**Steps:**
1. [ ] Download an image (jpg, png, gif)
2. [ ] Check for warnings

**Expected Results:**
```
✅ NO warning
✅ Risk: "SAFE"
✅ Color: GREEN
✅ Download completes immediately
```

**Document Result:**
```
Test 3.6 Status: [PASS / FAIL]
Risk Level: __________
```

---

### File Detection Summary

```
Test 3.1 (Executable): [✅ PASS / ❌ FAIL]
Test 3.2 (Batch): [✅ PASS / ❌ FAIL]
Test 3.3 (ZIP): [✅ PASS / ❌ FAIL]
Test 3.4 (IP Address): [✅ PASS / ❌ FAIL]
Test 3.5 (PDF): [✅ PASS / ❌ FAIL]
Test 3.6 (Image): [✅ PASS / ❌ FAIL]

Overall Status: [✅ PASS / ⚠️ PARTIAL / ❌ FAIL]
Completed: [ __ / 6 tests ]
```

---

## 🔗 Test 4: Redirect Chain Detection

### Setup (2 minutes)
1. [ ] Open DevTools: F12 → Network tab
2. [ ] Keep Network tab visible during tests

### Test 4.1: Malicious Redirect Chain

**Redirect Path:**
1. User clicks: `https://trusted-site.com/offer`
2. Redirects to: `https://shortener.tk/abc123`
3. Final: `https://phishing-site.xyz/login`

**Steps:**
1. [ ] Find or create a redirect chain (see Redirect Tools section)
2. [ ] Click the first link
3. [ ] Watch Network tab as redirects happen
4. [ ] Observe extension warning BEFORE reaching final site
5. [ ] Check what warning is shown

**Expected Results:**
```
Extension Warning Triggers:
✅ Before reaching phishing-site.xyz
✅ Message: "Redirect detected to suspicious site"
✅ Risk score reflects final destination (HIGH/CRITICAL)
✅ User can cancel/proceed

Network Tab Shows:
✅ All 3 redirects visible
✅ Status codes: 301/302/307
✅ Final destination clearly shown
```

**Document Result:**
```
Test 4.1 Status: [PASS / FAIL]
Warning Shown: [YES / NO]
Warning Timing: [BEFORE / DURING / AFTER] ✅ Should be BEFORE
Redirects Detected: [ __ / 3]
```

---

### Test 4.2: Legitimate Redirect

**Redirect Path:**
1. `https://bit.ly/example`
2. Final: `https://github.com/project`

**Steps:**
1. [ ] Click legitimate short link
2. [ ] Watch redirects happen
3. [ ] Observe final site

**Expected Results:**
```
✅ NO phishing warning
✅ bit.ly is trusted shortener
✅ github.com is trusted destination
✅ No security concerns
✅ Download happens normally
```

**Document Result:**
```
Test 4.2 Status: [PASS / FAIL]
Warnings Shown: [YES / NO] ✅ Should be NO
```

---

### Test 4.3: Redirect to Survey Scam

**Redirect Path:**
1. `https://trusted-company.com/offer`
2. Final: `https://survey-scam.tk/click`

**Steps:**
1. [ ] Click link
2. [ ] Observe redirects
3. [ ] Wait for warning

**Expected Results:**
```
✅ Warning triggered
✅ Message: "Suspicious redirect destination"
✅ Risk: MEDIUM/HIGH
✅ Recommendation: "Verify before proceeding"
```

**Document Result:**
```
Test 4.3 Status: [PASS / FAIL]
Warning Shown: [YES / NO]
```

---

### Test 4.4: Multiple Rapid Redirects

**Setup:**
1. [ ] Create redirect chain with 5+ steps
2. [ ] Each redirects quickly

**Steps:**
1. [ ] Click link
2. [ ] Watch Network tab
3. [ ] Count redirects
4. [ ] Check if extension handles all

**Expected Results:**
```
✅ Extension tracks all redirects
✅ NO crash with multiple redirects
✅ Final destination properly evaluated
✅ Performance not significantly impacted
✅ Warning only on suspicious final site
```

**Document Result:**
```
Test 4.4 Status: [PASS / FAIL]
Redirects Handled: [ __ / 5+]
Performance Impact: [NONE / MINOR / MAJOR]
```

---

### Redirect Detection Summary

```
Test 4.1 (Malicious Chain): [✅ PASS / ❌ FAIL]
Test 4.2 (Legitimate): [✅ PASS / ❌ FAIL]
Test 4.3 (Survey Scam): [✅ PASS / ❌ FAIL]
Test 4.4 (Multiple): [✅ PASS / ❌ FAIL]

Overall Status: [✅ PASS / ⚠️ PARTIAL / ❌ FAIL]
Completed: [ __ / 4 tests ]
```

---

## 📊 Final Test Summary

```
╔═══════════════════════════════════════════════════════════╗
║                   FINAL TEST RESULTS                      ║
╠═══════════════════════════════════════════════════════════╣
║ System 1: Email Detection      [ __ / 5 PASS]            ║
║ System 2: URL Detection        [ __ / 6 PASS]            ║
║ System 3: File Detection       [ __ / 6 PASS]            ║
║ System 4: Redirect Detection   [ __ / 4 PASS]            ║
╠═══════════════════════════════════════════════════════════╣
║ TOTAL TESTS PASSED:            [ __ / 21 PASS]           ║
║ SUCCESS RATE:                  [ __ %]                   ║
╠═══════════════════════════════════════════════════════════╣
║ OVERALL STATUS:                [✅ PASS / ⚠️ FAIL]        ║
╚═══════════════════════════════════════════════════════════╝
```

**Criteria:**
- ✅ PASS: 18+ / 21 tests passing (85%+)
- ⚠️ PARTIAL: 12-17 / 21 tests passing (57-80%)
- ❌ FAIL: < 12 / 21 tests passing (< 57%)

---

## 🔧 Redirect Tools (Optional)

### Simple Redirect Test
```bash
# Python one-liner to redirect
python -m http.server 8000

# Then create HTML:
<html>
<script>
window.location.href = 'https://final-destination.com';
</script>
</html>
```

### Using bit.ly
1. Create short link at bit.ly
2. Point to your test destination
3. Click to trigger redirect

---

**Print this page and follow step-by-step!**

Last Updated: 2026-03-14
