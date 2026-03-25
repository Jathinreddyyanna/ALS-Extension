# ⚡ Quick Reference: Demo Test Cases

**TL;DR version of VERIFICATION_CHECKLIST.md - Copy & paste ready**

---

## 🔴 Test Case Summary

### System 1: Gmail Phishing Email Detection

| Email Type | FROM | SUBJECT | Expected Risk | Color |
|-----------|------|---------|----------------|-------|
| **Phishing** | support@amazon-verify.tk | Account Suspended - Verify Immediately! | 75-100 CRITICAL | 🔴 |
| **Credential** | security@bank-login.ml | Update Your Banking Details | 60-85 HIGH | 🔴 |
| **Lottery** | noreply@lottery-scam.tk | Congratulations! You Won $1,000,000! | 65-85 HIGH | 🔴 |
| **Finance Fraud** | noreply@bank-alert.xyz | Transaction Alert - Verify Now | 55-75 MEDIUM/HIGH | 🟡 |
| **Legitimate** | noreply@teams.microsoft.com | You have a new message in Teams | 0-15 SAFE | 🟢 |

**All test emails available in Gmail drafts for easy testing**

---

### System 2: URL Phishing Detection

| URL | Expected Risk | Color | Key Signal |
|-----|----------------|-------|-----------|
| https://amazon-login-secure.xyz/account/verify | 85-95 CRITICAL | 🔴 | Subdomain abuse + Suspicious TLD |
| https://secure-login.amazon.com.verify.tk | 60-70 HIGH | 🟠 | Domain spoofing |
| https://amaz0n-login.xyz/account | 50-70 MEDIUM/HIGH | 🟡 | Typosquatting |
| https://amazon.in | 5 SAFE | 🟢 | Legitimate domain |
| https://github.com | 5 SAFE | 🟢 | Trusted domain |

**Testing:** Type URL in address bar → Wait 300ms for hover preview

---

### System 3: Suspicious File Downloads

| File | Type | Expected Risk | Action |
|------|------|----------------|--------|
| setup.exe | Executable | 🔴 CRITICAL | Block/Quarantine |
| script.bat | Batch File | 🔴 HIGH | Quarantine |
| documents.zip | Archive | 🟡 MEDIUM | Scan before opening |
| software.rar | Archive (IP source) | 🟡 MEDIUM | Verify source |
| resume.pdf | Document | 🟢 LOW | Allow |
| photo.jpg | Image | 🟢 SAFE | Allow |

**Testing:** Right-click file → "Save as..." → Check for warning

---

### System 4: Redirect Chain Detection

| Redirect Flow | Expected Behavior |
|---------------|-------------------|
| Trusted → Shortener → Phishing | ⚠️ Warn: "Redirect to suspicious site" |
| bit.ly → github.com | ✅ No warning (all trusted) |
| Trusted → Survey Scam | ⚠️ Warn: "Suspicious redirect" |
| Multiple rapid redirects | ✅ Tracks all, validates final destination |

**Testing:** Click link → Monitor redirects → Check warning

---

## ✅ 5-Minute Pre-Demo Checklist

```
☐ Extension loaded and enabled
☐ Backend service running (if needed)
☐ No console errors (F12)
☐ Test URLs bookmarked:
  - amazon-login-secure.xyz
  - amazon.in (comparison)
  - github.com (safe)
☐ Gmail drafts ready with test emails
☐ Network connection stable
☐ DevTools closed (professional view)
☐ Browser window maximized
☐ Cache cleared (optional)
```

---

## 🎬 Demo Flow (3-4 minutes)

### Opening (30 seconds)
- [ ] Open Chrome, show extension icon
- [ ] Explain: "AI-powered hybrid detection (ML + heuristics)"
- [ ] Mention: "240K URLs trained, 92% accuracy"

### Email Detection (1 minute)
- [ ] Open Gmail
- [ ] Show phishing email (amazon-verify.tk)
- [ ] "Notice the red highlight - AI detected phishing"
- [ ] Hover email → Show risk popup "89/100 CRITICAL"
- [ ] Explain signals: "Subdomain abuse, suspicious TLD, urgency language"

### URL Detection (1.5 minutes)
- [ ] Address bar: Type `amazon-login-secure.xyz`
- [ ] Wait for hover preview (show 85-95 score)
- [ ] "Same URL flagged as phishing"
- [ ] Compare: Type `amazon.in` → Show 5/100 SAFE
- [ ] Explain difference: "Our ML learned what makes URLs trustworthy"

### File Detection (30 seconds)
- [ ] Mention: "File downloads also protected"
- [ ] .exe files → CRITICAL ❌
- [ ] .pdf files → SAFE ✅

### Closing (30 seconds)
- [ ] Show stats: "Detection in < 100ms per URL"
- [ ] "Zero false positives on 6 legitimate sites"
- [ ] "Ready for production deployment"

---

## 🚨 Troubleshooting Quick Fixes

| Problem | Fix |
|---------|-----|
| Extension not responding | Reload: chrome://extensions/ → Refresh |
| Popup shows blank | Open DevTools (F12) → Check console for errors |
| Scoring is slow | Clear browser cache → Restart browser |
| Email not detected | Check Gmail UI hasn't changed (Gmail updates often) |
| No hover preview | Wait 300ms → Make sure extension icon shows enabled |
| Risk scores different each time | Cache may be corrupted → Clear cache & restart |

---

## 📊 Expected Performance Metrics

| Metric | Target | Status |
|--------|--------|--------|
| URL Scoring Latency | < 100ms | ✅ ~50-100ms |
| Cache Hit Latency | < 5ms | ✅ ~1-5ms |
| False Positive Rate | < 5% | ✅ 0% (validated) |
| Model Accuracy | > 90% | ✅ 92.34% |
| Memory Usage | < 50MB | ✅ Verified |

---

## 🎯 Success = Must Have

✅ **At least 2 systems working flawlessly**
✅ **No crashes during demo**
✅ **Risk scores displayed correctly**
✅ **Response time < 200ms**
✅ **Clear explanations**

---

## 📸 Key Stats to Mention

- **Model Performance:** 92.34% accuracy on 240K URLs
- **Training Data:** 651K URLs analyzed, 240K balanced dataset
- **Precision:** 93.16% (few false positives)
- **Recall:** 91.39% (catches real threats)
- **ROC-AUC:** 97.78% (excellent discrimination)
- **Detection Speed:** Sub-100ms per URL
- **False Positive Rate:** 0% on tested legitimate sites

---

**Print this page for quick reference during demo!**
